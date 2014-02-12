#!/usr/bin/env python
#
# Copyright 2014 cloudysunny14.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging

from ryu.base import app_manager
from ryu.exception import OFPUnknownVersion
from ryu.exception import RyuException
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

ARP_FLOW_PRIORITY = ofproto_v1_3_parser.UINT16_MAX - 1
OUTPUT_FLOW_PRIORITY = 1
# Built-in chain 
# [INPUT] - [PREFORWARD] -[FORWARD] - [OUTPUT]
MANGLE_INPUT_TABLE_ID = 0
MANGLE_PREFORWARD_TABLE_ID = 1
MANGLE_FORWARD_TABLE_ID = 2
MANGLE_OUTPUT_TABLE_ID = 3

MANGLE_DEFAULT_PRIORITY = 0
MANGLE_DEFAULT_COOKIE = 0
MANGLE_DEFAULT_COOKIE_MASK = 0
MANGLE_DEFAULT_TIMEOUT = 0

MANGLE_ACTION = 'action'
MANGLE_ACTION_ACCEPT = 'accept'
MANGLE_ACTION_DENY = 'deny'
MANGLE_ACTION_CONTROLLER = 'controller'
MANGLE_ACTION_ADD_DST_TO_ADDRESS_LIST = 'add-dst-to-address-list'
MANGLE_ACTION_ADD_SRC_TO_ADDRESS_LIST = 'add-src-to-address-list'
MANGLE_JUMP = 'jump'

MANGLE_JUMP_TARGET = 'jump-target'
MANGLE_ADDRESS_LIST = 'address-list'
MANGLE_DST_ADDRESS = 'dst-address'
MANGLE_SRC_ADDRESS = 'src-address'
MANGLE_DST_ADDRESS_LIST = 'dst-address-list'
MANGLE_SRC_ADDRESS_LIST = 'src-address-list'
MANGLE_PROTOCOL = 'protocol'
MANGLE_LIMIT = 'limit'

MANGLE_CHAIN = 'chain'
MANGLE_CHAIN_INPUT = 'input'
MANGLE_CHAIN_PREFORWARD = 'preforward'
MANGLE_CHAIN_FORWARD = 'forward'
MANGLE_CHAIN_OUTPUT = 'output'

MANGLE_NW_PROTO_TCP = 'tcp'
MANGLE_NW_PROTO_UDP = 'udp'
MANGLE_NW_PROTO_ICMP = 'icmp'

#TODO: Compatible with VLAN_ID
# Cookie mask format
# (LSB)  1       2       3   (MSB)4
# 0         12        20         32
# +----------+--------+-----------+
# |  vlan_id |  chain |   list    |
# +----------+--------+-----------+
MANGLE_ADDRESS_LIST_COOKIE_MASK = 0xFFF00000
MANGLE_CHAIN_COOKIE_MASK = 0xFF000
MANGLE_VLAN_ID_COOKIE_MASK = 0xFFF
MANGLE_ADDRESS_LIST_SHIFT = 20
MANGLE_CHAIN_LIST_SHIFT = 12

LOG = logging.getLogger(__name__)

class QoSLib(app_manager.RyuApp):
    """ Simple QoS library """
    def __init__(self):
        """initialization."""
        super(QoSLib, self).__init__()
        self.name = 'qoslib'
        #{datapath_id: switch}
        self.switches = {}
        #{datapath_id: {list_name: cookie}}
        self.lists = {}
        self.current_table_id = MANGLE_INPUT_TABLE_ID
        self.waiters = {}
        self.use_switch_flow = True

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        datapath = ev.msg.datapath
        switch = self.switches.get(datapath.id)
        switch.packet_in_handler(ev)

    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION or \
                dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    # for OpenFlow version1.0
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_0(self, ev):
        self.stats_reply_handler(ev)

    # for OpenFlow version1.2 or later
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        self.stats_reply_handler(ev)

    @staticmethod
    def mangle(datapath):
        mangle = _Mangle(datapath)
        return mangle

    @staticmethod
    def queue_tree(datapath):
        """"""

    def get_switch(self, datapath):
        switch = self.switches.get(datapath.id, None)
        if switch is None:
            switch = _Switch(datapath)
            self.switches[datapath.id] = switch
            if self.use_switch_flow:
                switch.set_arp_flow()
        return switch

    def add_mangle(self, mangle):
        if mangle.is_built:
            raise MangleAlreadyBuildError(mangle=mangle) 
        datapath = mangle.dp
        switch = self.get_switch(datapath)
        mangle.build(self.waiters, switch)
        properties = mangle.properties
        cookie = MANGLE_DEFAULT_COOKIE
        cookie_mask = MANGLE_DEFAULT_COOKIE_MASK
        priority = MANGLE_DEFAULT_PRIORITY
        table_id = MANGLE_INPUT_TABLE_ID
        hard_timeout = MANGLE_DEFAULT_TIMEOUT
        action = _Action(mangle, switch)
        actions = action.to_openflow()
        matches = _Match(mangle).to_openflow()
        if properties.has_key(MANGLE_CHAIN):
            table_id = switch.chains_to_table_id(properties[MANGLE_CHAIN])
        if mangle.has_address_list:
            list_dic = mangle.address_list_dict
            list_name = list_dic.keys()[0]
            cookie = switch.get_cookie_for_list(list_name,
                                                table_id)
        for match in matches:
            flow = self._to_of_flow(table_id, cookie, cookie_mask,
                                    priority, match, actions, hard_timeout)
            mangle.send_flow_mod(flow)
        if properties.has_key(MANGLE_LIMIT):
            pass

    def _to_of_flow(self, table_id, cookie, cookie_mask, priority,
                    match, actions, hard_timeout):
        flow = {'cookie': cookie,
                'cookie_mask': cookie_mask,
                'priority': priority,
                'table_id': table_id,
                'flags': 0,
                'idle_timeout': 0,
                'hard_timeout': hard_timeout,
                'match': match,
                'actions': actions}
        return flow

class MangleAlreadyBuildError(RyuException):
    message = 'Mangle is already build. : mangle=%(mangle)s'

class MangleAlreadyAddedListError(RyuException):
    message = 'Mangle is already build. : list_name=%(list_name)s,\
               list=%(list)s'

class MangleValidateError(RyuException):
    message = 'Mangle is not valid : msg=%(msg)s mangle=%(mangle)s'

class _Mangle(object):

    def __init__(self, datapath):
        self.dp = datapath
        self.ofctl = _OFCtl.create_ofctl(datapath)
        self.properties = {}
        self.is_built = False
        self.address_list_dict = {}
        self.has_address_list = False

    def add_property(self, p, v):
        if self.is_built:
           raise MangleAlreadyBuildError(mangle=self.properties)
        self.properties[p] = v
        return self

    def address_list(self, list_name, address_list):
        if self.has_address_list:
            name_list = self.address_list_dict.keys()[0]
            add_list = self.address_list_dict[name_list]
            raise MangleAlreadyAddedListError(list_name=name_list,
                                              list=add_list)
        self.has_address_list = True
        self.address_list_dict[list_name] = address_list

    def _validate_mangle(self, waiters, switch):
        """Validate mangle entry"""
        #Search flow table.etc
        msgs = self.ofctl.get_flow_stats(self.dp, waiters)
        if self.properties.has_key(MANGLE_ACTION_ACCEPT):
            table_id = self.properties.get(MANGLE_CHAIN, None)
            if table_id == MANGLE_OUTPUT_TABLE_ID:
                #Action accept is can't set to output chain.
                self.properties[MANGLE_CHAIN] = MANGLE_INPUT_TABLE_ID
                pass
        if self.properties.has_key(
                 MANGLE_ACTION_ADD_DST_TO_ADDRESS_LIST) or \
             self.properties.has_key(
                 MANGLE_ACTION_ADD_SRC_TO_ADDRESS_LIST):
               if not self.properties.has_key(MANGLE_ADDRESS_LIST):
                   return False, 'Action add list required to specify\
                                  list'
        if self.properties.has_key(MANGLE_DST_ADDRESS_LIST) or \
           self.properties.has_key(MANGLE_SRC_ADDRESS_LIST):
            list_name = self.properties.get(MANGLE_DST_ADDRESS_LIST,
                                self.properties[MANGLE_SRC_ADDRESS_LIST])
            if not self.address_list_dict.has_key(list_name) and \
                not switch.address_list.has_key(list_name):
                return False, 'Specify list is not exist'
            else:
                self.has_address_list = True
                
        if self.properties.has_key(MANGLE_JUMP):
            if not self.propoeries.has_key(MANGLE_JUMP_TARGET):
                return False, 'Action jump required to specify\
                               jump target.'

        LOG.debug('%s', msgs)
        return True, ''

    def build(self, waiters, switch):
        result, msg = self._validate_mangle(waiters, switch)
        if not result:
            raise MangleValidateError(msg=msg, mangle=self.properties)
        self.is_built = True
        return self

    def send_flow_mod(self, flow):
        cmd = self.dp.ofproto.OFPFC_ADD
        self.ofctl.mod_flow_entry(self.dp, flow, cmd)

class _Action(object):
    """"""
    def __init__(self, mangle, switch):
        self.mangle = mangle
        self.switch = switch

    def to_openflow(self):
        properties = self.mangle.properties
        if not properties.has_key(MANGLE_ACTION):
            raise Exception()
        value = properties[MANGLE_ACTION]
        actions = []
        if value == MANGLE_ACTION_ACCEPT:
            actions = [{'type': 'GOTO_TABLE',
                        'table_id': MANGLE_OUTPUT_TABLE_ID}]
        elif value == MANGLE_ACTION_ADD_DST_TO_ADDRESS_LIST or\
            value == MANGLE_ACTION_ADD_SRC_TO_ADDRESS_LIST:
            pass
        return actions

class _Match(object):
    """"""

    _CONVERT_DL_TYPE = {MANGLE_DST_ADDRESS:
                            {'dl_type': ether.ETH_TYPE_IP},
                        MANGLE_SRC_ADDRESS:
                            {'dl_type': ether.ETH_TYPE_IP},
                        MANGLE_PROTOCOL:
                            {'dl_type': ether.ETH_TYPE_IP}}

    _CONVERT_KEY = {MANGLE_DST_ADDRESS: 'ipv4_dst',
                    MANGLE_SRC_ADDRESS: 'ipv4_src',
                    MANGLE_PROTOCOL: 'nw_proto'}

    _CONVERT_PROTOCOL = {MANGLE_NW_PROTO_TCP: inet.IPPROTO_TCP,
                         MANGLE_NW_PROTO_UDP: inet.IPPROTO_UDP,
                         MANGLE_NW_PROTO_ICMP: inet.IPPROTO_ICMP}

    def __init__(self, mangle):
        self.mangle = mangle

    def _validate_match(self, match_property):
        if match_property.has_key(MANGLE_DST_ADDRESS):
            True
        return True


    def convert_match(self, match_property):
        match = {}
        for key, value in match_property.items():
            if key in _Match._CONVERT_DL_TYPE:
                dl_type = _Match._CONVERT_DL_TYPE[key]
                match.update(dl_type)
            if key in _Match._CONVERT_KEY:
                match_key = _Match._CONVERT_KEY[key]
                match_value = _Match._CONVERT_PROTOCOL.get(match_property[key],
                    match_property[key])
                match[match_key] = match_value
        return match

    def to_openflow(self):
        match_properties = self.mangle.properties
        if not self._validate_match(match_properties):
            return
        matches = []
        if self.mangle.has_address_list:
            if match_properties.has_key(MANGLE_SRC_ADDRESS_LIST):
                key = match_properties[MANGLE_SRC_ADDRESS_LIST]
                add_property_key = MANGLE_SRC_ADDRESS
            elif match_properties.has_key(MANGLE_DST_ADDRESS_LIST):
                key = match_properties[MANGLE_DST_ADDRESS_LIST]
                add_property_key = MANGLE_DST_ADDRESS

            address_list = self.mangle.address_list_dict.get(key, [])
            for address in address_list:
                match_properties[add_property_key] = address
                matches.append(self.convert_match(match_properties))
        else:
            matches.append(self.convert_match(match_properties))
        return matches

class _Switch(object):
    """ Switch """
    def __init__(self,
                 datapath,
                 chains={MANGLE_CHAIN_INPUT: MANGLE_INPUT_TABLE_ID,
                         MANGLE_CHAIN_PREFORWARD: MANGLE_PREFORWARD_TABLE_ID,
                         MANGLE_CHAIN_FORWARD: MANGLE_FORWARD_TABLE_ID,
                         MANGLE_CHAIN_OUTPUT: MANGLE_OUTPUT_TABLE_ID}):
        self.datapath = datapath
        self.chains = chains
        #{list_name: {cookie: cookie_value, cookie_mask: cookie_mask_value}}
        self.address_list = {}
        self.current_list_value = 0
        self.mac_to_port = {}

    def set_arp_flow(self):
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=self.datapath, priority=ARP_FLOW_PRIORITY,
                                match=match, instructions=inst)
        self.datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                table_id=MANGLE_OUTPUT_TABLE_ID,
                                priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _send_end_flows(self, datapath, in_port, out_port, eth):
        parser = datapath.ofproto_parser
        action_dst = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
        self.add_flow(datapath, OUTPUT_FLOW_PRIORITY, match, action_dst)
        match = parser.OFPMatch(in_port=out_port, eth_dst=eth.src)
        action_src = [parser.OFPActionOutput(in_port)]
        self.add_flow(datapath, OUTPUT_FLOW_PRIORITY, match, action_src)

    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        self.mac_to_port.setdefault(datapath.id, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[datapath.id][eth.src] = in_port

        if eth.dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self._send_end_flows(datapath, in_port, out_port, eth)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def chains_to_table_id(self, chain):
        if not self.chains.has_key(chain):
            raise Exception()
        return self.chains[chain]

    def get_cookie_for_list(self, list_name, table_id):
        if not self.address_list.has_key(list_name):
            self.current_list_value = self.current_list_value + 1
            cookie_value = (table_id << MANGLE_CHAIN_LIST_SHIFT) | \
                (self.current_list_value << MANGLE_ADDRESS_LIST_SHIFT)
            self.address_list[list_name] = cookie_value
        return self.address_list[list_name]

class _OFCtl(object):

    _OFCTL = {ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
              ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
              ofproto_v1_3.OFP_VERSION: ofctl_v1_3}

    @staticmethod
    def create_ofctl(datapath):
        version = datapath.ofproto.OFP_VERSION
        if version not in _OFCtl._OFCTL:
            raise OFPUnknownVersion(version=version)
        return _OFCtl._OFCTL[version]
