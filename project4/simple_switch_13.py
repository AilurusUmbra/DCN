# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

RED = 1
BLUE = 2
BLACK = 3

tenant = [[9, 12, 15, 3, 6],
        [10, 13, 16, 4, 1, 7],
        [11, 14, 2, 5, 8]]
vlan_table = [2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2]


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        """ Part 1: Isolate traffic of different tenant """
        # isolation check
        host_eth = "00:00:00:00:00:"
        if eth.dst[0:15] == host_eth and eth.src[0:15] == host_eth:
            dst_num = int(eth.dst[15:17], 16)
            src_num = int(eth.src[15:17], 16)
            
            print('-'*50)
            print("src: ", eth.src, src_num)
            print("dst: ", eth.dst, dst_num)
            
            tenant_group = vlan_table[src_num-1]
            print("group: ",tenant[tenant_group-1])
            if dst_num in tenant[tenant_group-1]:
                print("in!")
                print('-'*50)
            else: 
                print("no")
                print('-'*50)
                return

        # got dpid
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        
        """ Part 2: Isolate broadcast traffic """

        # for switches in filter_dpid[i], 
        # they should filter packets from i-th tenant
        entry_dpid=[4, 4, 5, 5, 7, 7, 8, 8, 11, 11, 12, 12, 14, 14, 15, 15]
        filter_dpid = [[4, 8, 14], [7, 12], [5, 11, 15]]
        leaf_dpid = sum(filter_dpid, []) # Just flatten filter_dpid
        #print("before", leaf_dpid)
        #print(src_num, entry_dpid[src_num-1])
        print("after", leaf_dpid)
        # filter broadcast packet
        broadcast_dst = "ff:ff:ff:ff:ff:ff"
        """if dst == broadcast_dst and eth.src[0:15] == host_eth and dpid in leaf_dpid:
            # Before pingall
            src_num = int(eth.src[15:17], 16)
            tenant_group = vlan_table[src_num-1]
            # filter all 
            if dpid in filter_dpid[tenant_group-1]:
                return
            else:

            print("group: ",tenant[tenant_group-1])
            if dst_num in tenant[tenant_group-1]:
            """
        if dst == broadcast_dst and eth.src[0:15] == host_eth: 
            src_num = int(eth.src[15:17], 16)
            tenant_group = vlan_table[src_num-1]
            leaf_dpid.remove(entry_dpid[src_num-1])
        print("dpid",dpid)
        if dst == broadcast_dst and eth.src[0:15] == host_eth and dpid in leaf_dpid:
        
            print("broadcast!",dpid)
            src_num = int(eth.src[15:17], 16)
            tenant_group = vlan_table[src_num-1]

            # 1
            if dpid == 11:
                if tenant_group == 1:
                    dst = host_eth + '09'
                elif tenant_group == 2:
                    dst = host_eth + '0a'
                else:
                    return
            # 2
            elif dpid == 12:
                if tenant_group == 1:
                    dst = host_eth + '0c'
                elif tenant_group == 2:
                    return
                else:
                    dst = host_eth + '0b'
            # 3
            elif dpid == 14:
                if tenant_group == 1:
                    return
                elif tenant_group == 2:
                    dst = host_eth + '0d'
                else:
                    dst = host_eth + '0e'
            # 4
            elif dpid == 15:
                if tenant_group == 1:
                    dst = host_eth + '0f'
                elif tenant_group == 2:
                    dst = host_eth + '10'
                else:
                    return
            # 5
            elif dpid == 5:
                if tenant_group == 1:
                    dst = host_eth + '03'
                elif tenant_group == 2:
                    dst = host_eth + '04'
                else:
                    return
            # 6
            elif dpid == 4:
                if tenant_group == 1:
                    return
                elif tenant_group == 2:
                    dst = host_eth + '01'
                else:
                    dst = host_eth + '02'
            # 7
            elif dpid == 7:
                if tenant_group == 1:
                    dst = host_eth + '06'
                elif tenant_group == 2:
                    return
                else:
                    dst = host_eth + '05'
            # 8
            elif dpid == 8:
                src_num = int(eth.src[15:17], 16)
                tenant_group = vlan_table[src_num-1]
                if tenant_group == 1:
                    return
                elif tenant_group == 2:
                    dst = host_eth + '07'
                else:
                    dst = host_eth + '08'
        print(dst)
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            #print("dpid:",dpid, self.mac_to_port[dpid])
            #print("dst:",dst, self.mac_to_port[dpid][dst], out_port)
        else:
            out_port = ofproto.OFPP_FLOOD
            #print("dst:",dst , out_port)

        src_num = int(eth.src[15:17], 16)
        if dpid == entry_dpid[src_num-1]:
            out_port = 3

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
