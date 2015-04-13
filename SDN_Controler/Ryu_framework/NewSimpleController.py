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

#======================================================================
#TO BE USED WITH mobilityPackage folder
#----------------------------------------------------------------------

# must be used with a mininet topology that has:
#     *A stricly related backbone
#     *The first interface of each router must be the local Network one

#----------------------------------------------------------------------
#TO FIX : make router solicitation accepted by hosts
#TO DO: ping handling / normal routing handling /
#       testing mobility flow set up
#======================================================================

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet.ipv6 import ipv6	
from ryu.lib.packet import icmpv6
from ryu.lib.packet.icmpv6 import nd_router_advert
from ryu.ofproto  import ether, inet


import ryu.controller.dpset   
import ryu.controller.network

import ryu.topology.switches
import ryu.topology.event
import ryu.topology.api

from ryu.mobilityPackage import mobilityTracker


# BCE = [] # Binding Cache Entry
# 
# class AnchorMAR(object):
# 	def __init__(self, mar, pref):
# 		self.mar = mar
# 		self.pref = pref
# class CacheEntry(object):
# 	def __init__(self, mn_id=None, current_mar=None, current_prefix =None, list_anchor_mar=None):
# 		self.mn_id = mn_id
# 		self.current_mar = current_mar
# 		self.current_prefix = current_prefix
# 		self.list_anchor_mar = list_anchor_mar
	

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #Static code working for 3 switches in triangle
    # MASK = 32
    # addressesSubNet12 = ['2000:12::1','2000:12::2']
    # addressesSubNet13 = ['2000:13::1','2000:13::3']
    # addressesSubNet23 = ['2000:23::2','2000:23::3']
    # addressesGW = ['2001::1','2002::1','2003::1']
    

    def __init__(self, *args, **kwargs):
       	super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        #switch and link list
        self.switchList = []
        self.linkList = []
        self.bindingList = {}
        self.mobTracker = mobilityTracker.MobilityTracker()
        self.tunnelID = 1
        #Constant set to TRUE at the FIrst packet reception
        self.RoutingDone = False


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #DATAPATH represents the switch that send OF message
        datapath = ev.msg.datapath
        #OFPROTO represents OpenFlow version used
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
 
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match,instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
        
#     @set_ev_cls(ryu.controller.ofp_event.EventOFPStateChange, CONFIG_DISPATCHER)
#     def node_adding(self,ev):
#     	print('#### NEW SWITCH ADDED ####')
#     	print(ev.datapath)
#     	self.switches.append(ev.datapath)
#     	
#     @set_ev_cls(ryu.controller.network.EventMacAddress, CONFIG_DISPATCHER)
#     def intf_adding(self,ev):
# 		print(ev.dp)
# 		print(ev.port)
# 		print('#### NEW MAC ADDED ####')
 

    #return output interface : from two SWITCHES ID
    def routing(self, source, dest):
        for l in listLinks:
            if l.src.dpid==source and l.dst.dpid==dest:
                return l.src.port_no
    
    #return MAC interface from DATAPATH_id and port_id
    def generateMAC(self, dpid, portid):
        addMAC = '0'+str(dpid)+':00:00:00:00:0'+str(portid)
        return addMAC
												
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print('********** NEW PACKET **********')
        if(self.RoutingDone==False):
            appManager = app_manager.RyuApp()
            self.switchList = ryu.topology.api.get_all_switch(appManager)
            #switchNames = [switch.dp.id for switch in listSwitch]
            self.linkList = ryu.topology.api.get_all_link(appManager)
            print(self.linkList)
            #linksConnection = [str(link.src.dpid)+str(link.src.port_no)+str(link.dst.dpid) for link in self.linkList]
            

            #Creating backbone IP @ and binding them to port and switches
            for link in self.linkList:
                if (link.src.dpid,link.src.port_no) not in self.bindingList and (link.dst.dpid,link.dst.port_no) not in self.bindingList :
                    self.bindingList[link.src.dpid,link.src.port_no] = '2000:'+str(link.src.dpid)+str(link.dst.dpid)+'::'+str(link.src.dpid)
                    self.bindingList[link.dst.dpid,link.dst.port_no] = '2000:'+str(link.src.dpid)+str(link.dst.dpid)+'::'+str(link.dst.dpid)
            print(self.bindingList)
            self.RoutingDone = True
        
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
 
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        i = pkt.get_protocols(ipv6)[0]
        dst = eth.dst
        src = eth.src
        pkt_type =0
         
        dpid = datapath.id
        print 'DPID::{}'.format(dpid)

        for p in pkt.protocols:
            if p.protocol_name == 'icmpv6':
                pkt_type=1
            if pkt_type == 1:
                print 'ICMPv6'	
                icmp = pkt.get_protocols(icmpv6.icmpv6)[0]
                #print 'ICMP type {}'.format(icmp.type_)
                itype = 0
                found = 0
                prefix =''
                if icmp.type_== 133:
                    print 'Router Solicitation'
                    itype = 1
                if icmp.type_== 134:
                    print 'Router Advertisement'
                    itype = 2
                if icmp.type_== 128:
                    print 'Echo Request'
                if icmp.type_== 129:
                    print 'Echo Reply'
                if icmp.type_ ==136:
                    print 'Neighbour Advertisement'
                    itype=3

                #        Authentication and prefix acquisition
                # file= open('/home/ubuntu/test.txt','r')
                # for line in file:
                #         if ((str(line).find(str(src)) != -1)&(str(line[57:]).find(str(dpid)) != -1 )):
                #                 found = 1
                #                 prefix=line[:38]				
                #                 break
                #         print 'Prefix:{}'.format(prefix)
                #         file.close()	


        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        #TEMPORARY SOLUTION
        found=1
        if((itype == 1)&(found == 1)):#Router Sollicitation
            print 'Authenticated User'
            found_bce = 0
            #create/update BCE
            
            #IMPLEMENT HERE THE TRAKING MODULE
            #host ID based on MAC address
            priorNetworks = self.mobTracker.getTraceAndUpdate(src,datapath);
            if priorNetworks is not None:
                #create tunnel with all the previous network and the current one
                for priorDp in priorNetworks[:-1]:
                    tunID = self.tunnelID
                    self.tunnelID += 1
                    
                    #prior Network SIDE:
                    
                    #Flow Network ---> Host
                    
                    #we must retreive what was the host @ in this network
                    #Compute old prefix
                    priorPrefix = str('200')+str(priorDp.id)+'::'
                    #Not sure but here @ is the concatenation of 
                    #Prefix and MAC @. If not working, @ recording must be set up!!!
                    
                    priorAddress = priorPrefix+src
                    
                    #MATCH : if incoming packets that try to reach host old @
                    matchOldInput = parser.OFPMatch(ipv6_dst=priorAddress)
                    
                    #ACTIONS : Decrement TTL (not enabled)+ encapsulate them in new VLAN+ forward them to the new router
                    actionsOldInput = []
                    actionsOldInput.extend([parser.OFPActionPushVlan(),parser.OFPActionSetField(vlan_vid=tunID)])
                    #Resolving output port
                    outputPortNb = self.routing(priorDp.id,dpid)
                    actionsOldInput.append(parser.OFPActionOutput(outputPortNb))
                    
                    #Pushing flow not considering BUFFER ID
                    self.add_flow(priorDp, 1, matchOldInput, actionsOldInput)

                    #Flow Network <--- Host
                    
                    #MATCH : from vlan
                    matchOldOutput = parser.OFPMatch(vlan_vid=tunID)
                    #ACTIONS : desencapsulate + loopback
                    actionsOldOutput = []
                    actionsOldOutput.append(parser.OFPActionPopVlan())
                    #!!!Need to find a solution : at worst asking flow table
                    actionsOldOutput.append(parser.LOOPBACK)
                    #Pushing flow not considering BUFFER ID
                    self.add_flow(priorDp, 1, matchOldOutput, actionsOldOutput)

                    #New Network Side:

                    #Flow Network <--- Host
                    
                    #MATCH : if outcoming packets that come from host old @
                    matchNewOutput = parser.OFPMatch(ipv6_src=priorAddress)
                    
                    #ACTIONS : Decrement TTL (not enabled)+ encapsulate them in new VLAN+ forward them to the new router
                    actionsNewOutput = []
                    actionsNewOutput.extend([parser.OFPActionPushVlan(),parser.OFPActionSetField(vlan_vid=tunID)])
                    #Resolving output port
                    outputPortNb2 = self.routing(dpid,priorDp.id)
                    actionsNewOutput.append(parser.OFPActionOutput(outputPortNb2))
                    #Pushing flow not considering BUFFER ID
                    self.add_flow(datapath, 1, matchNewOutput, actionsNewOutput)

                    #Flow Network --> Host
                    
                    #MATCH : from vlan
                    matchNewInput = parser.OFPMatch(vlan_vid=tunID)
                    #ACTIONS : desencapsulate + loopback
                    actionsNewInput = []
                    actionsNewInput.append(parser.OFPActionPopVlan())
                    #output on local network interface : number 1
                    actionsNewInput.append(parser.OFPActionOutput(1))
                    #Pushing flow not considering BUFFER ID
                    self.add_flow(datapath, 1, matchNewInput, actionsNewInput)
                    
            #ONCE FLOWS ARE SET UP PUSHING ROUTER ADVERTISEMENT

            #create RA including the allocated prefix (should consider multiple prefixes later) 
            out_port = in_port #direct reply
            pkt_generated = packet.Packet()
            e= ethernet.ethernet(dst=str(eth.src), src=self.generateMAC(dpid,in_port), ethertype=ether.ETH_TYPE_IPV6)
            #THE FIRST PORT MUST BE THE ONE TOWARD THE LAN!!!
            if in_port == 1: #this packet is not from the backbone -> must be from the local dependant NW : generated on the fly
                srcIP = '200'+str(dpid)+'::1'
            else:#otherwise use the bindingList
                srcIP = self.bindingList[dpid,in_port]
            ip = ipv6(nxt=inet.IPPROTO_ICMPV6, src=srcIP, dst=str(i.src))
            #setting up prefix : the dependant Local Network prefix is returned, it's get from addressesGW
            prefix = '200'+str(dpid)+'::'
            
            icmp_v6 = icmpv6.icmpv6(type_=icmpv6.ND_ROUTER_ADVERT, data=icmpv6.nd_router_advert(ch_l=64, rou_l=3000, options=[icmpv6.nd_option_pi(length=4, pl=64, res1=7, val_l=86400, pre_l=14400, prefix=prefix)]))
            #pkt_ra = e/ip/icmp_v6
            pkt_generated.add_protocol(e)
            pkt_generated.add_protocol(ip)
            pkt_generated.add_protocol(icmp_v6)
            pkt_generated.serialize()

            print repr(pkt_generated.data)
 
            #dpid = datapath.id
            #self.mac_to_port.setdefault(dpid, {})
            #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
 
            # learn a mac address to avoid FLOOD next time.
            # self.mac_to_port[dpid][src] = in_port
 				
            # if dst in self.mac_to_port[dpid]:
            #     out_port = self.mac_to_port[dpid][dst]
            # else:
            #     out_port = ofproto.OFPP_FLOOD
 
 
            actions = [parser.OFPActionOutput(out_port)]	
            #data = None
            #if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            #    data = msg.data
 		
            #out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
            out_ra = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=0, actions=actions, data=pkt_generated.data)
 
            #datapath.send_msg(out)
            datapath.send_msg(out_ra)
            print('********** router adv sent **********')
            return
        else:
            print ('other message')
 			
     #     elif itype ==3:
     #    		print 'Neighbour Advertisement'
     #    		#dpid = datapath.id
     #    		#self.mac_to_port.setdefault(dpid, {})
     #    		#self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
     #    		#self.mac_to_port[dpid][src] = in_port			
     #    		out_port = ofproto.OFPP_FLOOD#self.mac_to_port[dpid][dst]
 			
 
     #    		actions = [parser.OFPActionOutput(out_port)]
     #    		data = None
     #    		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
     #    		    data = msg.data		
 
     #    		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
     #    					          in_port=in_port, actions=actions, data=data)
 
     #    		datapath.send_msg(out)
     #    		return   
     #     elif itype!=2: #Not RS, NA, and RA			
     #    		#dpid = datapath.id
     #    		#self.mac_to_port.setdefault(dpid, {})
     #    		#self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
 
     #    		# learn a mac address to avoid FLOOD next time.
     #    		#self.mac_to_port[dpid][src] = in_port
 				
     #    		if dst in self.mac_to_port[dpid]:
     #    		    out_port = self.mac_to_port[dpid][dst]
     #    		else:
     #    		    out_port = ofproto.OFPP_FLOOD
 
 
     #    		actions = [parser.OFPActionOutput(out_port)]
     #    		# install a flow to avoid packet_in next time
     #    		if out_port != ofproto.OFPP_FLOOD:
     #    		    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
     #    		    # flow_mod & packet_out
     #    		    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
     #    			self.add_flow(datapath, 1, match, actions, msg.buffer_id)
     #    			return
     #    		    else:
     #    			self.add_flow(datapath, 1, match, actions)
     #    		data = None
     #    		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
     #    		    data = msg.data
 		
 
     #    		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
     #    					          in_port=in_port, actions=actions, data=data)
 
     #    		datapath.send_msg(out)
     #    		return  
 
     #    else: # not ICMPv6 packet.
     # # should be verify later
     #    	#dpid = datapath.id
     #    	#self.mac_to_port.setdefault(dpid, {})
     #    	#self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
     #    	# learn a mac address to avoid FLOOD next time.
     #    	#self.mac_to_port[dpid][src] = in_port
 				
     #    	if dst in self.mac_to_port[dpid]:
     #    	    out_port = self.mac_to_port[dpid][dst]
     #    	else:
     #    	    out_port = ofproto.OFPP_FLOOD
 
     #    	actions = [parser.OFPActionOutput(out_port)]
     #    	# install a flow to avoid packet_in next time
     #    	if out_port != ofproto.OFPP_FLOOD:
     #    	    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
     #    	    # verify if we have a valid buffer_id, if yes avoid to send both
     #    	    # flow_mod & packet_out
     #    	    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
     #    		self.add_flow(datapath, 1, match, actions, msg.buffer_id)
     #    		return
     #    	    else:
     #    		self.add_flow(datapath, 1, match, actions)
     #    	data = None
     #    	if msg.buffer_id == ofproto.OFP_NO_BUFFER:
     #    	    data = msg.data
 
     #    	out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
     #    	datapath.send_msg(out)
     #    	return
