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
from ryu.lib.packet import ipv4
from ryu.lib.of_config.capable_switch import OFCapableSwitch
import ryu.lib.of_config.classes as ofc

IPV4 = ipv4.ipv4.__name__
OUTPUT_CONTROLLER = 0xfffffffd
ARP_FLOW_PRIORITY = ofproto_v1_3_parser.UINT16_MAX - 1
OUTPUT_FLOW_PRIORITY = ofproto_v1_3_parser.UINT16_MAX >> 1
NORMAL_FLOW_PRIORITY = ofproto_v1_3_parser.UINT16_MAX >> 2
# Built-in chain
# [INPUT] - [PREFORWARD] -[FORWARD] - [OUTPUT]
#TODO: repeal this rules
MANGLE_INPUT_TABLE_ID = 0
MANGLE_PREFORWARD_TABLE_ID = 1
MANGLE_FORWARD_TABLE_ID = 2
MANGLE_OUTPUT_TABLE_ID = 3

MANGLE_DEFAULT_PRIORITY = 0
MANGLE_DEFAULT_COOKIE = 0
MANGLE_DEFAULT_COOKIE_MASK = 0xFFFFFFFF
MANGLE_DEFAULT_TIMEOUT = 0

MANGLE_ACTION = 'action'
MANGLE_ACTION_ACCEPT = 'accept'
MANGLE_ACTION_DENY = 'deny'
MANGLE_ACTION_CONTROLLER = 'controller'
MANGLE_ACTION_ADD_DST_TO_ADDRESS_LIST = 'add-dst-to-address-list'
MANGLE_ACTION_ADD_SRC_TO_ADDRESS_LIST = 'add-src-to-address-list'
MANGLE_ACTION_MARK_PACKET = 'mark-packet'
MANGLE_JUMP = 'jump'
MANGLE_QUEUE = 'queue'
MANGLE_PRIORITY = 'priority'

MANGLE_JUMP_TARGET = 'jump-target'
MANGLE_ADDRESS_LIST = 'address-list'
MANGLE_DST_ADDRESS = 'dst-address'
MANGLE_SRC_ADDRESS = 'src-address'
MANGLE_DST_ADDRESS_LIST = 'dst-address-list'
MANGLE_SRC_ADDRESS_LIST = 'src-address-list'
MANGLE_PROTOCOL = 'protocol'
MANGLE_LIMIT = 'limit'
MANGLE_NEW_PACKET_MARK = 'new-packet-mark'

MANGLE_PACKET_MARK = 'packet-mark'
MANGLE_DST_MAC_ADDRESS = 'dst-mac-address'
MANGLE_SRC_MAC_ADDRESS = 'src-mac-address'
MANGLE_DST_PORT = 'dst-port'

MANGLE_CHAIN = 'chain'
MANGLE_CHAIN_INPUT = 'input'
MANGLE_CHAIN_PREFORWARD = 'preforward'
MANGLE_CHAIN_FORWARD = 'forward'
MANGLE_CHAIN_OUTPUT = 'output'

MANGLE_NW_PROTO_ICMP = 'icmp'
MANGLE_NW_PROTO_TCP = 'tcp'
MANGLE_NW_PROTO_UDP = 'udp'

# TODO: Compatible with VLAN_ID
# Cookie mask format
# (LSB)                          (MSB)
# +-------------+---------+---------+
# | 0 |  1 ~ 12 | 13 ~ 19 | 20 ~ 32 |
# +---+---------+---------+---------+
# |src|         |         |         |
# |or | vlan_id |  chain  |   list  |
# |dst|         |         |         |
# +---+---------+---------+---------+
# Note:src or dst bit is only uses add-address-list action,
#      default value is 0.
MANGLE_ADDRESS_LIST_COOKIE_MASK = 0xFFF00000
MANGLE_CHAIN_COOKIE_MASK = 0xFE000
MANGLE_VLAN_ID_COOKIE_MASK = 0x1FFE
MANGLE_SD_COOKIE_MASK = 0x1
MANGLE_ADDRESS_LIST_SHIFT = 20
MANGLE_CHAIN_LIST_SHIFT = 13

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
        self.use_switch_flow = True

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        datapath = ev.msg.datapath
        switch = self.switches.get(datapath.id)
        switch.packet_in_handler(ev)

    @staticmethod
    def mangle(datapath):
        mangle = _Mangle(datapath)
        return mangle

    @staticmethod
    def queue_tree(peer, datapath):
        queue_tree = _QueueTree(peer, datapath)
        return queue_tree

    def get_switch(self, datapath):
        switch = self.switches.get(datapath.id, None)
        LOG.info("switch:%s", switch)
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
        mangle.build(switch)
        properties = mangle.properties
        cookie_mask = MANGLE_DEFAULT_COOKIE_MASK
        priority = properties.get(MANGLE_PRIORITY, 
            MANGLE_DEFAULT_PRIORITY)
        hard_timeout = MANGLE_DEFAULT_TIMEOUT
        action = _Action(mangle, switch)
        matches = _Match(mangle, switch).to_openflow()
        table_id = mangle.table_id
        cookie = mangle.cookie
        for match, add_next_table in matches:
            actions = action.to_openflow()
            if add_next_table:
                goto_table_action = action.get_next_table()
                if goto_table_action is not None:
                    actions.append(goto_table_action)

            flow = QoSLib.to_of_flow(table_id, cookie, cookie_mask,
                                     priority, match, actions,
                                     hard_timeout)
            mangle.send_flow_mod(flow)
            if mangle.has_list_action:
                switch.register_actions(mangle.list_name, cookie, actions)
        if MANGLE_LIMIT in properties:
            pass
        
    @staticmethod
    def to_of_flow(table_id, cookie, cookie_mask, priority,
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

    def register_queue(self, queue):
        """"""
        resources = []
        switch = self.get_switch(queue.datapath)
        if queue.name in switch.queues.keys():
            resources = switch.queues[queue.name].keys()
        elif len(switch.queues.values()):
            for queues in queue.queue_ids.values():
                filled_res = reduce(lambda ql, qr: ql + qr,
                                       switch.queues.values())
                f_queue = list(set(queues) - set(filled_res))
                if len(f_queue):
                    resources.append(f_queue[0])
        else:
            for queues in queue.queue_ids.values():
                if len(queues):
                    resources.append(queues[0])
        if not len(resources):
            raise Exception()
        queue_id_mapping = queue.get_queue_mapping(resources)
        switch.queues[queue.name] = queue_id_mapping
        queue.edit_config(resources)


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
        self.cookie = MANGLE_DEFAULT_COOKIE
        self.table_id = MANGLE_INPUT_TABLE_ID
        self.list_name = None
        self.has_list_action = False

    def add_property(self, p, v):
        if self.is_built:
            raise MangleAlreadyBuildError(mangle=self.properties)
        self.properties[p] = v
        return self

    def address_list(self, list_name, address_list):
        if len(self.address_list_dict):
            name_list = self.address_list_dict.keys()[0]
            add_list = self.address_list_dict[name_list]
            raise MangleAlreadyAddedListError(list_name=name_list,
                                              list=add_list)
        self.address_list_dict[list_name] = address_list

    def _validate_mangle(self, switch):
        """Validate mangle entry"""
        # Search flow table.etc
        mangle_chain = self.properties.get(MANGLE_CHAIN,
            MANGLE_CHAIN_INPUT)
        self.table_id = switch.chains_to_table_id(mangle_chain)

        if MANGLE_ACTION_ACCEPT in self.properties:
            table_id = self.properties.get(MANGLE_CHAIN, None)
            if table_id == MANGLE_OUTPUT_TABLE_ID:
                # Action accept is can't set to output chain.
                self.properties[MANGLE_CHAIN] = MANGLE_INPUT_TABLE_ID
                pass

        list_name = self.properties.get(MANGLE_ADDRESS_LIST, None) 
        if MANGLE_ACTION_ADD_DST_TO_ADDRESS_LIST in self.properties or \
           MANGLE_ACTION_ADD_SRC_TO_ADDRESS_LIST in self.properties:
            if MANGLE_ADDRESS_LIST not in self.properties:
                return False, 'Action add list required to specify\
                                  list'
        if MANGLE_DST_ADDRESS_LIST in self.properties:
            list_name = self.properties[MANGLE_DST_ADDRESS_LIST]
            self.has_list_action = True
        if MANGLE_SRC_ADDRESS_LIST in self.properties:
            list_name = self.properties[MANGLE_SRC_ADDRESS_LIST]
            self.has_list_action = True

        if list_name is not None:
            if list_name not in self.address_list_dict and \
               list_name not in switch.address_list:
                return False, 'Specify list is not exist'
            else:
                priority = self.properties.get(MANGLE_PRIORITY, 
                    MANGLE_DEFAULT_PRIORITY)
                chain = self.properties.get(MANGLE_CHAIN,
                    MANGLE_CHAIN_INPUT)
                switch.put_address_list(list_name,
                    self.address_list_dict.get(list_name, []),
                    priority, chain)

        is_src = MANGLE_ACTION_ADD_SRC_TO_ADDRESS_LIST in \
                self.properties
        if list_name is not None:
            self.cookie = switch.get_cookie_for_list(list_name,
                self.table_id, is_src)
            self.list_name = list_name

        if MANGLE_PACKET_MARK in self.properties:
            mark = self.properties[MANGLE_PACKET_MARK]
            value = switch.get_dscp_value(mark)
            self.properties[MANGLE_PACKET_MARK] = value
        
        if MANGLE_ACTION_MARK_PACKET in self.properties:
            if MANGLE_NEW_PACKET_MARK not in self.properties:
                return False, 'Action mark-packet required to specify\
                               new-packet-mark property'
        
        return True, ''

    def build(self, switch):
        result, msg = self._validate_mangle(switch)
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

    def get_next_table(self):
        properties = self.mangle.properties
        value = properties[MANGLE_ACTION]
        table_id = properties.get(MANGLE_CHAIN,
            MANGLE_INPUT_TABLE_ID)
        if value == MANGLE_ACTION_ACCEPT:
            table_id = MANGLE_OUTPUT_TABLE_ID
        elif MANGLE_JUMP in properties:
            table_name = properties[MANGLE_JUMP]
            if table_name == MANGLE_CHAIN_PREFORWARD:
                table_id = MANGLE_PREFORWARD_TABLE_ID
            elif table_name == MANGLE_CHAIN_FORWARD:
                table_id = MANGLE_FORWARD_TABLE_ID
            elif table_name == MANGLE_CHAIN_OUTPUT:
                table_id = MANGLE_OUTPUT_TABLE_ID
            elif table_name == MANGLE_CHAIN_INPUT:
                pass
            else: 
                table_id = self.switch.chains_to_table_id(
                    properties[MANGLE_JUMP])
        elif table_id == MANGLE_CHAIN_INPUT:
            table_id = MANGLE_PREFORWARD_TABLE_ID
        elif table_id == MANGLE_CHAIN_PREFORWARD:
            table_id = MANGLE_FORWARD_TABLE_ID
        elif table_id == MANGLE_CHAIN_FORWARD:
            table_id = MANGLE_OUTPUT_TABLE_ID

        if table_id != MANGLE_INPUT_TABLE_ID:
            return {'type': 'GOTO_TABLE',
                    'table_id': table_id}
        return None
        
    def to_openflow(self):
        properties = self.mangle.properties
        if MANGLE_ACTION not in properties:
            raise Exception()
        value = properties[MANGLE_ACTION]
        LOG.info("value:%s", value)
        actions = []
        if value == MANGLE_ACTION_ADD_DST_TO_ADDRESS_LIST or\
                value == MANGLE_ACTION_ADD_SRC_TO_ADDRESS_LIST:
            actions.append({'type': 'OUTPUT',
                'port': OUTPUT_CONTROLLER})
            return actions
        elif value == MANGLE_ACTION_MARK_PACKET:
            key = properties[MANGLE_NEW_PACKET_MARK]
            value = self.switch.mark_packet(key)
            actions.append({'type': 'SET_FIELD',
                'field': 'ip_dscp',
                'value': value})

        if MANGLE_QUEUE in properties:
            queue_name = properties[MANGLE_QUEUE]
            queue_id = self.switch.get_queue_id(queue_name)
            queue_action = {'type': 'SET_QUEUE',
                            'queue_id': queue_id}
            if len(actions) > 0:
                actions.append(queue_action)
            else:
                actions = [queue_action]
                
        return actions
   

class _Match(object):

    """"""

    _CONVERT_PREREQ = {MANGLE_DST_ADDRESS:
                      {'dl_type': ether.ETH_TYPE_IP},
                      MANGLE_SRC_ADDRESS:
                      {'dl_type': ether.ETH_TYPE_IP},
                      MANGLE_PROTOCOL:
                      {'dl_type': ether.ETH_TYPE_IP},
                      MANGLE_PACKET_MARK:
                      {'dl_type': ether.ETH_TYPE_IP},
                      MANGLE_ACTION_MARK_PACKET:
                      {'dl_type': ether.ETH_TYPE_IP},
                      MANGLE_DST_PORT:
                      {'dl_type': ether.ETH_TYPE_IP, 
                       'nw_proto': inet.IPPROTO_TCP}}

    _CONVERT_KEY = {MANGLE_DST_ADDRESS: 'ipv4_dst',
                    MANGLE_SRC_ADDRESS: 'ipv4_src',
                    MANGLE_PROTOCOL: 'nw_proto',
                    MANGLE_PACKET_MARK: 'ip_dscp',
                    MANGLE_DST_MAC_ADDRESS: 'eth_dst',
                    MANGLE_SRC_MAC_ADDRESS: 'eth_src',
                    MANGLE_DST_PORT: 'tp_dst'}

    _CONVERT_PROTOCOL = {MANGLE_NW_PROTO_TCP: inet.IPPROTO_TCP,
                         MANGLE_NW_PROTO_UDP: inet.IPPROTO_UDP,
                         MANGLE_NW_PROTO_ICMP: inet.IPPROTO_ICMP}

    def __init__(self, mangle, switch):
        self.mangle = mangle
        self.switch = switch

    def _validate_match(self, match_property):
        if MANGLE_DST_ADDRESS in match_property:
            True
        return True

    def to_openflow(self):
        match_properties = self.mangle.properties
        action = match_properties.get(MANGLE_ACTION, None)
        if not self._validate_match(match_properties):
            return
        matches = []
        key = None 
        next_table = False 
        if MANGLE_SRC_ADDRESS_LIST in match_properties:
            key = match_properties[MANGLE_SRC_ADDRESS_LIST]
            add_property_key = MANGLE_SRC_ADDRESS
        elif MANGLE_DST_ADDRESS_LIST in match_properties:
            key = match_properties[MANGLE_DST_ADDRESS_LIST]
            add_property_key = MANGLE_DST_ADDRESS
        elif MANGLE_ACTION_ADD_SRC_TO_ADDRESS_LIST in \
            match_properties.values() or \
            MANGLE_ACTION_ADD_DST_TO_ADDRESS_LIST in \
            match_properties.values():
            pass
        else:
            next_table = True

        address_list = self.switch.get_address_list(key)
        for address in address_list:
            address_match = {add_property_key: address}
            matches.append((_Match.convert_match(address_match, action),
               True))

        # In case of address list, not append match
        # because match field only required to address lists
        if not len(address_list):
            matches.append((_Match.convert_match(match_properties,
                action), next_table))

        return matches

    @staticmethod
    def convert_match(match_dict, action):
        match = {}
        for key, value in match_dict.items():
            if key in _Match._CONVERT_PREREQ:
                prereq = _Match._CONVERT_PREREQ[key]
                match.update(prereq)
                
            if key in _Match._CONVERT_KEY:
                match_key = _Match._CONVERT_KEY[key]
                match_value = \
                  _Match._CONVERT_PROTOCOL.get(match_dict[key],
                      match_dict[key])
                match.update({match_key: match_value})
        if action is not None:
            if action in _Match._CONVERT_PREREQ:
                prereq = _Match._CONVERT_PREREQ[action]
                match.update(prereq)
        return match
            

class _Switch(object):

    """ Switch """

    def __init__(self,
                 datapath,
                 chains={MANGLE_CHAIN_INPUT: 
                             MANGLE_INPUT_TABLE_ID,
                         MANGLE_CHAIN_PREFORWARD:
                             MANGLE_PREFORWARD_TABLE_ID,
                         MANGLE_CHAIN_FORWARD:
                             MANGLE_FORWARD_TABLE_ID,
                         MANGLE_CHAIN_OUTPUT:
                             MANGLE_OUTPUT_TABLE_ID}):
        self.datapath = datapath
        self.ofctl = _OFCtl.create_ofctl(datapath)
        self.chains = chains
        # {list_name: {list_action: {cookie:[action..]},
        #  {cookie:[action ..]..}, address:[adress..], ..}
        self.address_list = {}
        self.current_list_value = 0
        self.mac_to_port = {}
        # {queue_name: {resource_id: queue_id, ...}}
        self.queues = {}
        # {mark: dscp, ..}
        self.dscp_mark_mapping = {}
        self.current_dscp = 1

    def put_address_list(self, list_name, address_list,
        priority, chain):
        if list_name not in self.address_list:
            self.address_list[list_name] = {}
            self.address_list[list_name]['address'] = []
        address = self.address_list[list_name]['address']
        address = address + address_list
        self.address_list[list_name]['address'] = address
        priorities = self.address_list[list_name].get('priority', {})
        priorities[chain] = priority
        self.address_list[list_name]['priority'] = priorities
        LOG.info("put_list%s, %s" % (self.address_list, list_name))

    def get_address_list(self, list_name):
        lists = self.address_list.get(list_name, {})
        return lists.get('address', [])

    def set_arp_flow(self):
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(
            datapath=self.datapath, priority=ARP_FLOW_PRIORITY,
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

    def register_actions(self, list_name, cookie, actions):
        address_list = self.address_list.get(list_name, {})
        list_action = address_list.get('list_action', {})
        list_action[cookie] = actions
        address_list['list_action'] = list_action
        self.address_list[list_name] = address_list
        LOG.info('register_action:%s', self.address_list)

    def _send_end_flows(self, datapath, in_port, out_port, eth):
        parser = datapath.ofproto_parser
        action_dst = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
        self.add_flow(datapath, OUTPUT_FLOW_PRIORITY, match, action_dst)
        match = parser.OFPMatch(in_port=out_port, eth_dst=eth.src)
        action_src = [parser.OFPActionOutput(in_port)]
        self.add_flow(datapath, OUTPUT_FLOW_PRIORITY, match, action_src)

    def _get_all_cookies(self):
        all_cookies = {}
        for key in self.address_list.keys():
            list_actions = self.address_list[key].get('list_action', {})
            for cookie in list_actions.keys():
                all_cookies[cookie] = key
        return all_cookies

    def _create_cookie_list(self, list_name):
        cookies = []
        if list_name in self.address_list:
            list_action = \
                self.address_list[list_name].get('list_action', {})
            for cookie in list_action.keys():
                cookies.append(cookie)
        return cookies

    def _update_list(self, list_name, chain,
        cookie, address, is_src, priority):
        """ Update list actions with correspod
        to list actions """
        address_list = self.address_list[list_name]['address']
        if address not in address_list:
            address_list.append(address)
        LOG.info('list_action_update_list:%s', self.address_list)
        list_action = self.address_list[list_name]['list_action']
        actions = list_action.get(cookie, [])
        
        add_property_key = MANGLE_DST_ADDRESS
        if is_src:
            add_property_key = MANGLE_SRC_ADDRESS
            
        match = {add_property_key: address}
        match = _Match.convert_match(match, None)
        table_id = self.chains_to_table_id(chain)
        next_table_id = table_id + 1 
        next_table_action = {'type': 'GOTO_TABLE',
            'table_id': next_table_id}
        if next_table_action not in actions:
            actions.append(next_table_action)

        LOG.info('match:%s', match)
        # Address that was added later to set a high priority
        flow = QoSLib.to_of_flow(table_id, cookie,
            MANGLE_DEFAULT_COOKIE_MASK, priority + 1, 
            match, actions, 0)
        LOG.info("send_flows:%s", flow)
        cmd = self.datapath.ofproto.OFPFC_ADD
        self.ofctl.mod_flow_entry(self.datapath, flow, cmd)
        self.datapath.send_barrier()

    def _add_list(self, msg, list_name):
        pkt = packet.Packet(msg.data)
        header_list = dict((p.protocol_name, p)
                           for p in pkt.protocols if type(p) != str)
        if header_list:
            if IPV4 in header_list:
                LOG.info("Address list:%s, %s" % (self.address_list, list_name))
                cookies = self._create_cookie_list(list_name)
                in_cookie = msg.cookie
                is_src = in_cookie & MANGLE_SD_COOKIE_MASK
                if is_src:
                    address = header_list[IPV4].src
                else:
                    address = header_list[IPV4].dst
               
                for cookie in cookies:
                    table_id = (cookie & MANGLE_CHAIN_COOKIE_MASK) >> \
                        MANGLE_CHAIN_LIST_SHIFT
                    priorities = self.address_list[list_name]['priority']
                    chain = self.table_id_to_chain(table_id)
                    priority = priorities.get(chain, 0)
                    self._update_list(list_name, chain, cookie,
                        address, is_src, priority)
        
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        cookie = msg.cookie
        all_cookie = self._get_all_cookies()
        LOG.info('all_cookie:%s, cookie:%d'%(all_cookie, cookie))
        if cookie in all_cookie.keys():
            self._add_list(msg, all_cookie[cookie])

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

        out = parser.OFPPacketOut(datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data)
        datapath.send_msg(out)

    def chains_to_table_id(self, chain):
        if chain not in self.chains:
            raise Exception()
        return self.chains[chain]

    def table_id_to_chain(self, table_id):
        for k,v in self.chains.iteritems():
            if v == table_id:
                return k

    def get_cookie_for_list(self, list_name, table_id, is_src):
        cookies = self._create_cookie_list(list_name)
        if len(cookies):
            # All lists are same list value
            list_value = cookies[0] & MANGLE_ADDRESS_LIST_COOKIE_MASK
            list_value = list_value >> MANGLE_ADDRESS_LIST_SHIFT
        else:
            self.current_list_value = self.current_list_value + 1
            list_value = self.current_list_value
            
        cookie_value = is_src | \
            (table_id << MANGLE_CHAIN_LIST_SHIFT) | \
            (list_value << MANGLE_ADDRESS_LIST_SHIFT)
        list_action = self.address_list[list_name].get('list_action', {})
        if cookie_value not in cookies:
            list_action[cookie_value] = []
            self.address_list[list_name]['list_action'] = list_action 
        LOG.info('get_cookie_for_list:%s', self.address_list)
        return cookie_value

    def mark_packet(self, mark):
        LOG.info("mark:%s", mark)
        dscp = self.dscp_mark_mapping.get(mark, self.current_dscp)
        if mark not in self.dscp_mark_mapping:
            self.dscp_mark_mapping[mark] = dscp
            self.current_dscp = dscp + 1
        return dscp

    def get_dscp_value(self, mark):
        if mark not in self.dscp_mark_mapping:
            raise Exception()
        return self.dscp_mark_mapping[mark]

    def get_queue_id(self, queue_name):
        if queue_name not in self.queues:
            raise Exception()
        queue_ids = self.queues[queue_name].values()
        return queue_ids[0]

def _str_to_dpid(dpid):
    dpid_str = str(dpid)
    if dpid_str.find(':'):
        dpid_str = ''.join(dpid_str.split(':'))
    return int(dpid_str[:12], 16)

OF_CONFIG_TARGET = 'running'

class _QueueTree(object):

    """ Queue Settins """

    def __init__(self, peer, datapath):
        self.peer = peer
        self.datapath = datapath
        self.queues = {}
        self.capable_switch = None
        self.name = None
        self.max_rate = 0
        self.min_rate = 0
        #{port_id: [queue_ids...],}
        self.queue_ids = {} 

    def _validation(self):
        if not isinstance(self.peer, OFCapableSwitch):
            return False, 'Peer is not configuration point.'
        return True, ''

    def queue(self, name, min_rate, max_rate):
        """"""
        result, msg = self._validation()
        if not result:
            #TODO: 
            raise Exception()
        self.name = name 
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.capable_switch = self.peer.get()
        for logical_switch in self.capable_switch.logical_switches.switch:
            datapath_id = _str_to_dpid(logical_switch.datapath_id)
            if self.datapath.id == datapath_id:
                resources = logical_switch.resources
                for port_id in resources.port:
                    self.queue_ids[port_id] = []
                for queue_id in logical_switch.resources.queue:
                    for port_id in self.queue_ids.keys():
                        queue_list = []
                        if str(queue_id).startswith(str(port_id)):
                            queue_list = self.queue_ids[str(port_id)]
                        queue_list.append(str(queue_id))
                        self.queue_ids[port_id] = queue_list

    def get_queue_mapping(self, resources):
        capable_resources = self.capable_switch.resources.queue
        queue_id_map = {}
        for queue in capable_resources:
            queue_resource_id = str(queue.resource_id)
            if queue_resource_id in resources:
                queue_id_map[queue_resource_id] = str(queue.id)
        if len(set(queue_id_map.values())) > 1:
            # Incorrect queue sequence.
            raise Exception()
        return queue_id_map

    def edit_config(self, resources):
        capable_switch_id = self.capable_switch.id
        for queue in resources:
            try:
                capable_switch = ofc.OFCapableSwitchType(
                    id=capable_switch_id,
                    resources=ofc.OFCapableSwitchResourcesType(
                        queue=[
                            ofc.OFQueueType(
                                resource_id=queue,
                                properties=ofc.OFQueuePropertiesType(
                                    max_rate=self.max_rate,
                                    min_rate=self.min_rate))
                        ]
                    )
                )
            except TypeError:
                print "argument error"
                return
            try:
                self.peer.edit_config(OF_CONFIG_TARGET, capable_switch)
            except Exception, e:
               print e

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
