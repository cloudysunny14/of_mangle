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
"""
How to run this test

edit linc config file. LINC-Switch/rel/linc/releases/1.0/sys.config
You can find the sample config I used for the test below:

[
 {linc,
  [
   {of_config, enabled},
   {capable_switch_ports,
    [
      {port, 1, [{interface, "tap0"}]},
      {port, 2, [{interface, "tap1"}]}
    ]},
   {capable_switch_queues,
    [
    ]},
   {logical_switches,
    [
     {switch, 0,
      [
       {backend, linc_us4},
       {controllers,
        [
         {"Switch0-DefaultController", "localhost", 6633, tcp}
        ]},
       {queues_status, disabled},
       {ports, [
                {port, 1, {queues, []}},
                {port, 2, {queues, []}}
               ]}
      ]}
    ]}
  ]},
 {enetconf,
  [
   {capabilities, [{base, {1, 1}},
                   {startup, {1, 0}},
                   {'writable-running', {1, 0}}]},
   {callback_module, linc_ofconfig},
   {sshd_ip, any},
   {sshd_port, 1830},
   {sshd_user_passwords,
    [
     {"linc", "linc"}
    ]}
  ]},
 {lager,
  [
   {handlers,
    [
     {lager_console_backend, info},
     {lager_file_backend,
      [
       {"log/error.log", error, 10485760, "$D0", 5},
       {"log/console.log", info, 10485760, "$D0", 5}
      ]}
    ]}
  ]},
 {sasl,
  [
   {sasl_error_logger, {file, "log/sasl-error.log"}},
   {errlog_type, error},
   {error_logger_mf_dir, "log/sasl"},      % Log directory
   {error_logger_mf_maxbytes, 10485760},   % 10 MB max file size
   {error_logger_mf_maxfiles, 5}           % 5 files max
  ]},
 {sync,
  [
   {excluded_modules, [procket]}
  ]}
].

Then run linc
# sudo rel/linc/bin/linc console

Then run ryu
# cd of_mangle
# export RYUHOME=$HOME/ryu
# PYTHONPATH=$RYUHOME:. $RYUHOME/bin/ryu-manager --verbose\
    tests/test_of_mangle.py
"""
import logging

from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller.handler import set_ev_cls
from ryu.exception import OFPUnknownVersion
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.lib import hub
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from app import qoslib

LOG = logging.getLogger(__name__)
LOG_TEST_FINISH = 'TEST_FINISHED: Tests=[%s] (OK=%s NG=%s SKIP=%s)'


def get_flow_stats(dp, waiters, ofctl):
    table_id = dp.ofproto.OFPTT_ALL
    flags = 0
    out_port = dp.ofproto.OFPP_ANY
    out_group = dp.ofproto.OFPG_ANY
    cookie = 0
    cookie_mask = 0
    match = dp.ofproto_parser.OFPMatch()

    stats = dp.ofproto_parser.OFPFlowStatsRequest(
        dp, flags, table_id, out_port, out_group, cookie, cookie_mask,
        match)

    msgs = []
    ofctl.send_stats_request(dp, stats, waiters, msgs)

    flows = []
    for msg in msgs:
        for stats in msg.body:
            actions = ofctl.actions_to_str(stats.instructions)
            match = ofctl.match_to_str(stats.match)

            s = {'priority': stats.priority,
                 'cookie': stats.cookie,
                 'idle_timeout': stats.idle_timeout,
                 'hard_timeout': stats.hard_timeout,
                 'actions': actions,
                 'match': match,
                 'table_id': stats.table_id}
            flows.append(s)
    flows = {str(dp.id): flows}

    return flows


def delete_all_flows(dp):
    match = dp.ofproto_parser.OFPMatch()
    m = dp.ofproto_parser.OFPFlowMod(dp, 0, 0, dp.ofproto.OFPTT_ALL,
                                     dp.ofproto.OFPFC_DELETE,
                                     0, 0, 0, 0xffffffff,
                                     dp.ofproto.OFPP_ANY,
                                     dp.ofproto.OFPG_ANY,
                                     0, match, [])

    dp.send_msg(m)


class OFMangleTester(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'dpset': dpset.DPSet,
                 'qoslib': qoslib.QoSLib}

    _OFCTL = {ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
              ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
              ofproto_v1_3.OFP_VERSION: ofctl_v1_3}

    def __init__(self, *args, **kwargs):
        super(OFMangleTester, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.qoslib = kwargs['qoslib']
        self.qoslib.use_switch_flow = False
        self.waiters = {}
        self.pending = []
        self.results = {}

        for t in dir(self):
            if t.startswith("test_"):
                self.pending.append(t)
        self.pending.sort(reverse=True)

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

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_handler(self, ev):
        # Target switch datapath
        self.dp = ev.dp
        version = self.dp.ofproto.OFP_VERSION
        if version not in self._OFCTL:
            raise OFPUnknownVersion(version=version)
        self.ofctl = self._OFCTL[version]
        hub.spawn(self._do_test)

    def test_action_accept(self):
        mangle = qoslib.QoSLib.mangle(self.dp)
        mangle.add_property('action', 'accept').\
            add_property('dst-address', '10.0.0.2').\
            add_property('chain', 'forward')
        self.qoslib.add_mangle(mangle)
        msg = get_flow_stats(self.dp, self.waiters, self.ofctl)
        flow = msg[msg.keys()[0]][0]
        return ({'hard_timeout': 0, 'actions': ['GOTO_TABLE:3'], 'priority': 0,
                 'idle_timeout': 0, 'cookie': 0, 'table_id': 2,
                 'match': {'dl_type': 2048, 'nw_dst': '10.0.0.2'}} == flow)

    def test_action_list(self):
        mangle = qoslib.QoSLib.mangle(self.dp)
        mangle.address_list('first', ['10.0.0.2', '10.0.0.3'])
        mangle.add_property('action', 'accept').\
            add_property('dst-address-list', 'first').\
            add_property('chain', 'forward')
        self.qoslib.add_mangle(mangle)
        msg = get_flow_stats(self.dp, self.waiters, self.ofctl)
        flow = msg[msg.keys()[0]]
        return ([{'hard_timeout': 0, 'actions': ['GOTO_TABLE:3'],
                  'priority': 0, 'idle_timeout': 0, 'cookie': 1056768,
                  'table_id': 2, 'match': {'dl_type': 2048, 'nw_dst': '10.0.0.3'}},
                 {'hard_timeout': 0, 'actions': ['GOTO_TABLE:3'],
                  'priority': 0, 'idle_timeout': 0, 'cookie': 1056768,
                  'table_id': 2,
                  'match': {'dl_type': 2048, 'nw_dst': '10.0.0.2'}}] == flow)

    def _print_results(self):
        LOG.info("TEST_RESULTS:")
        ok = 0
        ng = 0
        skip = 0
        for t in sorted(self.results.keys()):
            if self.results[t] is True:
                ok += 1
            else:
                ng += 1
            LOG.info("    %s: %s", t, self.results[t])
        LOG.info(LOG_TEST_FINISH, len(self.pending), ok, ng, skip)

    def _do_test(self):
        """"""
        for test in self.pending:
            delete_all_flows(self.dp)
            self.dp.send_barrier()
            self.results[test] = getattr(self, test)()
        self._print_results()
