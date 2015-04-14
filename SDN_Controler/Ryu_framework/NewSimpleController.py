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
#MUST BE EXECUTED WITH --observe-link OPTION
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

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
       	super(SimpleSwitch13, self).__init__(*args, **kwargs)
        #Attribute not used
        self.mac_to_port = {}
        #switches list obtained from the app_manager
        self.switchList = []
        #links List obtained from the app_manager
        self.linkList = []
        #dictionary set up for routing purpose :
        #(datapathID,port_no) is associated to the one hope neighbor
        self.bindingList = {}
        #keep trace of the previous visited network
        self.mobTracker = mobilityTracker.MobilityTracker()
        #Vlan identifier to be incremented whil they are created
        self.tunnelID = 1
        #As no special event triggered when the systeme is on
        #main mode, the routing configuration is done at the
        #reception of the first message : then set to TRUE untill
        #the end.
        self.RoutingDone = False

    #All ready written function
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        #Datapath that has sent the OF message
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

    #Already written function : enable the controller to send flow 
    #instructions : action and matches to a given switch
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
 
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match,instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
      

    #return the port number from witch the datapath with 
    #dpid = source can reach the datapath with dpid = dest
    def routing(self, source, dest):
        for l in listLinks:
            if l.src.dpid==source and l.dst.dpid==dest:
                return l.src.port_no
    
    #return the MAC address associated DATAPATH_id and port_id
    def generateMAC(self, dpid, portid):
        addMAC = '0'+str(dpid)+':00:00:00:00:0'+str(portid)
        return addMAC
												
    #Packet handler
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print("===============NEW PACKET===============")
        
        # If you hit this you might want to increase 
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",ev.msg.msg_len, ev.msg.total_len)

        #Extracting Message informations
        #Topology stuff
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        #Protocol stuff
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        i = pkt.get_protocol(ipv6)
        #if it's not related to IPV6, not considered
        if i is None:
            print("----------NON IPV6 PACKET----------")
            print pkt
            print("========================================")
            return 0
        print("------------IPV6 PACKET------------")


        #If it's the first ipv6 packet received routing must be done before
        if(self.RoutingDone==False):
            #All the topology informations are obtained from the app_manager
            appManager = app_manager.RyuApp()
            #Collecting switches and links informations
            self.switchList = ryu.topology.api.get_all_switch(appManager)
            #switchNames = [switch.dp.id for switch in listSwitch]
            self.linkList = ryu.topology.api.get_all_link(appManager)
            #linksConnection = [str(link.src.dpid)+str(link.src.port_no)+str(link.dst.dpid) for link in self.linkList]
            
            #Once topology is known, addresses IP are distributed:
            #Creating backbone IP and binding them to port and switches
            for link in self.linkList:
                if (link.src.dpid,link.src.port_no) not in self.bindingList and (link.dst.dpid,link.dst.port_no) not in self.bindingList :
                    self.bindingList[link.src.dpid,link.src.port_no] = '2000:'+str(link.src.dpid)+str(link.dst.dpid)+'::'+str(link.src.dpid)
                    self.bindingList[link.dst.dpid,link.dst.port_no] = '2000:'+str(link.src.dpid)+str(link.dst.dpid)+'::'+str(link.dst.dpid)
            print('ROUTING DONE')
            print(self.bindingList)
            #The routing is done only once
            self.RoutingDone = True

        dst = eth.dst
        src = eth.src
        pkt_type =0
         
        dpid = datapath.id
        print 'DPID::{}'.format(dpid)
        
        #Examining protocols in the IP packet
        for p in pkt.protocols:
            if p.protocol_name == 'icmpv6':
                pkt_type=1
            if pkt_type == 1:
                print("-----------------ICMPv6-----------------")	
                icmp = pkt.get_protocols(icmpv6.icmpv6)[0]
                #print 'ICMP type {}'.format(icmp.type_)
                itype = 0
                found = 0
                prefix =''
                if icmp.type_== 133:
                    print 'Type : Router Solicitation'
                    itype = 1
                if icmp.type_== 134:
                    print 'Type : Router Advertisement'
                    itype = 2
                if icmp.type_== 128:
                    print 'Type : Echo Request'
                if icmp.type_== 129:
                    print 'Type : Echo Reply'
                if icmp.type_ ==136:
                    print 'Type : Neighbour Advertisement'
                    itype=3
                else:
                    print 'Type : other ICMPV6 message'

        
        #mac_to_port is not used 
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        print("Details : packet in ", dpid, src, dst, in_port)
        print("========================================")

        #once protocols are known, it's time to prepare answers
 
        #temporary solution : here no authentication protocol
        #every user are granted
        found=1
        
        #In case of Router Sollicitation
        if((itype == 1)&(found == 1)):
            
            #Mobility Management Procedure is fired
            
            #Asking for the list of the prior network
            #And updating it with the current one
            #host ID based on MAC address
            #the currrent datapath is also provided
            priorNetworks = self.mobTracker.getTraceAndUpdate(src,datapath);
            #if the list is empty there is nothing more to do
            #if not tunnels must be set up:
            if priorNetworks is not None:

                #creating tunnels with all the previous network and the current one
                for priorDp in priorNetworks[:-1]:
                    #Getting new tunnel identifier
                    tunID = self.tunnelID
                    self.tunnelID += 1
                    
                    #prior Network SIDE:
                    
                    #Flow Network ---> Host : 
                    #Handling incomming packets with the old host @
                    #as destination @

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
                    
                    #TODO : How mac addresses are set ?

                    #Pushing flow not considering BUFFER ID
                    self.add_flow(priorDp, 1, matchOldInput, actionsOldInput)

                    #Flow Network <--- Host
                    #Handling packets that comes from the tunnel

                    #MATCH : packets from vlan
                    matchOldOutput = parser.OFPMatch(vlan_vid=tunID)
                    #ACTIONS : desencapsulate + loopback
                    actionsOldOutput = []
                    actionsOldOutput.append(parser.OFPActionPopVlan())
                    #TODO !!!Need to find a solution : at worst asking flow table
                    #once decapsulated packet it has to be routed normally
                    #maybe output on ingress port...
                    actionsOldOutput.append(parser.LOOPBACK)

                    #Pushing flow not considering BUFFER ID
                    self.add_flow(priorDp, 1, matchOldOutput, actionsOldOutput)

                    #New Network Side:

                    #Flow Network <--- Host:
                    #Handling outgoing packets with old host @
                    #as source @
                    
                    #MATCH : if outcoming packets with host old @ as src @
                    matchNewOutput = parser.OFPMatch(ipv6_src=priorAddress)
                    
                    #ACTIONS : Decrement TTL (not enabled)+ encapsulate them in new VLAN+ forward them to the new router
                    actionsNewOutput = []
                    actionsNewOutput.extend([parser.OFPActionPushVlan(),parser.OFPActionSetField(vlan_vid=tunID)])
                    #Resolving output port
                    outputPortNb2 = self.routing(dpid,priorDp.id)
                    actionsNewOutput.append(parser.OFPActionOutput(outputPortNb2))
                    #Pushing flow not considering BUFFER ID
                    self.add_flow(datapath, 1, matchNewOutput, actionsNewOutput)

                    #Flow Network --> Host:
                    #Handling packets that comes from the tunnel
                    
                    #MATCH : packets that come from vlan
                    matchNewInput = parser.OFPMatch(vlan_vid=tunID)
                    #ACTIONS : desencapsulate + forward on local network
                    actionsNewInput = []
                    actionsNewInput.append(parser.OFPActionPopVlan())
                    #output on local network interface : number 1
                    actionsNewInput.append(parser.OFPActionOutput(1))
                    #Pushing flow not considering BUFFER ID
                    self.add_flow(datapath, 1, matchNewInput, actionsNewInput)
                    
            #once flows are set up, router advertisement has to be sent

            #create RA including the allocated prefix (should consider multiple prefixes later) 
            
            #direct reply on the incomming switch port
            out_port = in_port 
            pkt_generated = packet.Packet()
            e= ethernet.ethernet(dst=str(eth.src), src=self.generateMAC(dpid,in_port), ethertype=ether.ETH_TYPE_IPV6)
            #the first port must be the one toward the lan!!!
            if in_port == 1: #this packet is not from the backbone -> must be from the local dependant NW : generated on the fly
                srcIP = '200'+str(dpid)+'::1'
            else:#otherwise use the bindingList
                srcIP = self.bindingList[dpid,in_port]
            ip = ipv6(nxt=inet.IPPROTO_ICMPV6, src=srcIP, dst=str(i.src))
            #setting up prefix : the dependant Local Network prefix is returned
            prefix = '200'+str(dpid)+'::'
            
            icmp_v6 = icmpv6.icmpv6(type_=icmpv6.ND_ROUTER_ADVERT, data=icmpv6.nd_router_advert(ch_l=64, rou_l=3000, options=[icmpv6.nd_option_pi(length=4, pl=64, res1=7, val_l=86400, pre_l=14400, prefix=prefix)]))
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
 
            #ACTION : the RA must be forwarded on the incomming switch port
            actions = [parser.OFPActionOutput(out_port)]	

            #data = None
            #if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            #    data = msg.data
 		
            #out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
            out_ra = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=0, actions=actions, data=pkt_generated.data)
 
            #datapath.send_msg(out)
            datapath.send_msg(out_ra)
            print('>>>>> router advertisement sent <<<<<')
            return
        else:
            print ('')
 			
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