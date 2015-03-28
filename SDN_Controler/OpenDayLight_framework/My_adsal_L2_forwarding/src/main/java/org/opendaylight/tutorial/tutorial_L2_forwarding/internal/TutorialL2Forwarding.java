/*
 * Copyright (C) 2014 SDN Hub

 Licensed under the GNU GENERAL PUBLIC LICENSE, Version 3.
 You may not use this file except in compliance with this License.
 You may obtain a copy of the License at

    http://www.gnu.org/licenses/gpl-3.0.txt

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 implied.

 *
 */

package org.opendaylight.tutorial.tutorial_L2_forwarding.internal;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.lang.String;
import java.util.Map;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleException;
import org.osgi.framework.FrameworkUtil;
import org.opendaylight.controller.sal.core.ConstructionException;
import org.opendaylight.controller.sal.core.Host;
import org.opendaylight.controller.sal.core.Node;
import org.opendaylight.controller.sal.core.NodeConnector;
import org.opendaylight.controller.sal.core.Property;
import org.opendaylight.controller.sal.flowprogrammer.IFlowProgrammerService;
import org.opendaylight.controller.sal.flowprogrammer.Flow;
import org.opendaylight.controller.sal.packet.ARP;
import org.opendaylight.controller.sal.packet.BitBufferHelper;
import org.opendaylight.controller.sal.packet.Ethernet;
import org.opendaylight.controller.sal.packet.IDataPacketService;
import org.opendaylight.controller.sal.packet.IListenDataPacket;
import org.opendaylight.controller.sal.packet.IPv4;
import org.opendaylight.controller.sal.packet.Packet;
import org.opendaylight.controller.sal.packet.PacketResult;
import org.opendaylight.controller.sal.packet.RawPacket;
import org.opendaylight.controller.sal.action.Action;
import org.opendaylight.controller.sal.action.Output;
import org.opendaylight.controller.sal.action.Flood;
import org.opendaylight.controller.sal.action.SetDlDst;
import org.opendaylight.controller.sal.action.SetDlSrc;
import org.opendaylight.controller.sal.match.Match;
import org.opendaylight.controller.sal.match.MatchType;
import org.opendaylight.controller.sal.match.MatchField;
import org.opendaylight.controller.sal.utils.EtherTypes;
import org.opendaylight.controller.sal.utils.Status;
import org.opendaylight.controller.sal.utils.NetUtils;
import org.opendaylight.controller.switchmanager.ISwitchManager;
import org.opendaylight.controller.switchmanager.Subnet;






public class TutorialL2Forwarding implements IListenDataPacket {
    private static final Logger logger = LoggerFactory
            .getLogger(TutorialL2Forwarding.class);
    private ISwitchManager switchManager = null;
    private IFlowProgrammerService programmer = null;
    private IDataPacketService dataPacketService = null;
    private Map<Node, Map<InetAddress, NodeConnector>> ip_to_port_per_switch = new HashMap<Node, Map<InetAddress, NodeConnector>>();
    //router sees all the nodes as directly linked to him, the MAC address is in fact
    //the one of the next hop.
    private Map<Node, Map<InetAddress, byte[][]>> ip_to_mac_destANDlocal = new HashMap<Node, Map <InetAddress, byte[][]>>();
    
    private String function = "router";
   // private Map<InetAddress, NodeConnector> ip_to_port = new HashMap<InetAddress, NodeConnector>();
    
    
    //MAC & IP ADRESSES ASSIGNEMENT use 
    
    private final byte[] hw_eth1_router = {0,0,0,0,0,0x03};
    private final String ip_eth1_router = "10.0.1.1";
    private final byte[] hw_eth2_router = {0,0,0,0,0,0x04};
    private final String ip_eth2_router = "10.0.2.1";
    
    void setDataPacketService(IDataPacketService s) {
        this.dataPacketService = s;
    }

    void unsetDataPacketService(IDataPacketService s) {
        if (this.dataPacketService == s) {
            this.dataPacketService = null;
        }
    }

    public void setFlowProgrammerService(IFlowProgrammerService s)
    {
        this.programmer = s;
    }

    public void unsetFlowProgrammerService(IFlowProgrammerService s) {
        if (this.programmer == s) {
            this.programmer = null;
        }
    }

    void setSwitchManager(ISwitchManager s) {
        logger.debug("SwitchManager set");
        this.switchManager = s;
    }

    void unsetSwitchManager(ISwitchManager s) {
        if (this.switchManager == s) {
            logger.debug("SwitchManager removed!");
            this.switchManager = null;
        }
    }

    /**
     * Function called by the dependency manager when all the required
     * dependencies are satisfied
     *
     */
    void init() {
        logger.info("Initialized");
        // Disabling the SimpleForwarding and ARPHandler bundle to not conflict with this one
        BundleContext bundleContext = FrameworkUtil.getBundle(this.getClass()).getBundleContext();
        for(Bundle bundle : bundleContext.getBundles()) {
            if (bundle.getSymbolicName().contains("simpleforwarding")) {
                try {
                    bundle.uninstall();
                } catch (BundleException e) {
                    logger.error("Exception in Bundle uninstall "+bundle.getSymbolicName(), e); 
                }   
            }   
        } 
        //TODO filling IP_to_port table
        
 
    }

    /**
     * Function called by the dependency manager when at least one
     * dependency become unsatisfied or when the component is shutting
     * down because for example bundle is being stopped.
     *
     */
    void destroy() {
    }

    /**
     * Function called by dependency manager after "init ()" is called
     * and after the services provided by the class are registered in
     * the service registry
     *
     */
    void start() {
        logger.info("Started");
    }

    /**
     * Function called by the dependency manager before the services
     * exported by the component are unregistered, this will be
     * followed by a "destroy ()" calls
     *
     */
    void stop() {
        logger.info("Stopped");
    }

    private void floodPacket(RawPacket inPkt) {
        NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();
        Node incoming_node = incoming_connector.getNode();

        Set<NodeConnector> nodeConnectors =
                this.switchManager.getUpNodeConnectors(incoming_node);

        for (NodeConnector p : nodeConnectors) {
            if (!p.equals(incoming_connector)) {
                try {
                    RawPacket destPkt = new RawPacket(inPkt);
                    destPkt.setOutgoingNodeConnector(p);
                    this.dataPacketService.transmitDataPacket(destPkt);
                } catch (ConstructionException e2) {
                    continue;
                }
            }
        }
    }

    @Override
    public PacketResult receiveDataPacket(RawPacket inPkt) {
        if (inPkt == null) {
            return PacketResult.IGNORED;
        }

        logger.trace("Received a frame of size: {}",
                        inPkt.getPacketData().length);
        
        Packet formattedPak = this.dataPacketService.decodeDataPacket(inPkt);
        NodeConnector incoming_connector = inPkt.getIncomingNodeConnector();
        Node incoming_node = incoming_connector.getNode();
        
        System.out.println("Received a frame of size:" +
                inPkt.getPacketData().length + " on interface "+incoming_connector.toString());
        
        if (formattedPak instanceof Ethernet) {
        	byte[] srcMAC = ((Ethernet)formattedPak).getSourceMACAddress();
            byte[] dstMAC = ((Ethernet)formattedPak).getDestinationMACAddress();
            long srcMAC_val = BitBufferHelper.toNumber(srcMAC);
            long dstMAC_val = BitBufferHelper.toNumber(dstMAC);

            Packet nextPak = formattedPak.getPayload();
            
            
            try {
            	String class_pck = nextPak.getClass().toString();
	             System.out.println("Type of the received packet : __"+class_pck+"__");   
                if (nextPak instanceof ARP) {
	            	 	ARP arpPak = (ARP) nextPak;	            
                        byte[] senderProtAddr = arpPak.getSenderProtocolAddress();
                        byte[] targetProtAddr = arpPak.getTargetProtocolAddress();
                        byte[] senderHwAddr = arpPak.getSenderHardwareAddress();
                        System.out.println("ARP Frame received");
                		System.out.println("-> "+senderProtAddr+" at "+senderHwAddr+"looks for "+targetProtAddr);
                        try {
                            InetAddress arpTargetIP = InetAddress.getByAddress(targetProtAddr);
                            InetAddress arpSenderIP = InetAddress.getByAddress(senderProtAddr);

                            logger.warn("Arp packet: src {}, dst {}", arpSenderIP, arpTargetIP);
                            
                            InetAddress ip_eth1 = InetAddress.getByName(this.ip_eth1_router);
                            byte[] mac_eth1 = this.hw_eth1_router.clone();
                            InetAddress ip_eth2 = InetAddress.getByName(this.ip_eth2_router);
                            byte[] mac_eth2 = this.hw_eth2_router.clone();
                            
                            //ASKING FOR ip_eth1
                            
                            if (arpTargetIP.equals(ip_eth1)) {
                                sendARPReply(incoming_connector, mac_eth1, ip_eth1, senderHwAddr, arpSenderIP);
                                return PacketResult.CONSUME;
                            }
                            
                          //ASKING FOR ip_eth2
                            else if (arpTargetIP.equals(ip_eth2)) {
                                sendARPReply(incoming_connector, mac_eth2, ip_eth2, senderHwAddr, arpSenderIP);
                                return PacketResult.CONSUME;
                            }
                        } catch (UnknownHostException e) {
                        	//TODO
                        	System.out.println("aie!"+e.getMessage()+" ---- "+e.getLocalizedMessage());
                        
                        }                			
                	}
                	
                	//CASE 1 : IP PACKET
                	if (nextPak instanceof IPv4) {
						InetAddress srcIP;
						
						srcIP = InetAddress.getByAddress(NetUtils.intToByteArray4(((IPv4)nextPak).getSourceAddress()));
	                	InetAddress dstIP = InetAddress.getByAddress(NetUtils.intToByteArray4(((IPv4)nextPak).getDestinationAddress()));
						
	                	System.out.println("IP packet received from " + srcIP.toString() + " to : " + dstIP.toString() +"on port " + incoming_connector + "  @  " + incoming_node +" Ethertype : "+((Ethernet)formattedPak).getEtherType() );
	                	
	                	//1 hop routing : learning
	                	
	                	//TABLES INITIALISATION : 1st packet received
	                    if (this.ip_to_port_per_switch.get(incoming_node) == null) {
	                         this.ip_to_port_per_switch.put(incoming_node, new HashMap<InetAddress, NodeConnector>());  
	                    }
	                    if (this.ip_to_mac_destANDlocal.get(incoming_node) == null) {
	                         this.ip_to_mac_destANDlocal.put(incoming_node, new HashMap<InetAddress, byte[][]>());  
	                    }
	            
	                    //Filling tables
	                    if ( (this.ip_to_port_per_switch.get(incoming_node).put(srcIP, incoming_connector)) == null){
	                    	System.out.println("new entry in the table for IP = "+srcIP);
	                    }
	                    //update if already existing
	                    byte[][] mac_destANDlocal = {srcMAC,dstMAC};
	                    this.ip_to_mac_destANDlocal.get(incoming_node).put(srcIP, mac_destANDlocal);
	                    
	                    
	                	//forwarding
	                    NodeConnector dst_connector = this.ip_to_port_per_switch.get(incoming_node).get(dstIP);
	                    byte[][] resolved_macs = this.ip_to_mac_destANDlocal.get(incoming_node).get(dstIP);
	                    //is a interface set for the @IP dest
	                    if (dst_connector != null && resolved_macs != null) {
	                    	System.out.println("IP packet must be transmitted on : " + dst_connector + " @ " + incoming_node);
	                    	//defining the match
	                    	Match match = new Match();
	                    	match.setField(MatchType.DL_TYPE, (short) 0x0800);
	                    	match.setField(MatchType.IN_PORT, incoming_connector);
	                        match.setField(MatchType.NW_DST, dstIP);
	                        List<Action> actions = new ArrayList<Action>();
	                        //defining new dest MAC addr
	                        actions.add(new SetDlDst(resolved_macs[0]));
	                        //defining new src MAC addr
	                        actions.add(new SetDlSrc(resolved_macs[1]));
	                        //defining output interface
	                        actions.add(new Output(dst_connector));
	             
	                        
	                        Flow f = new Flow(match, actions);
	                        f.setPriority((short)512);
	                        Status status = programmer.addFlow(incoming_node, f);
	                        if (!status.isSuccess()) {
	                            System.out.println(
	                                    "SDN Plugin failed to program the flow: "+ f +" The failure is: {}"+
	                                    status.getDescription());
	                            return PacketResult.IGNORED;
	                        }
	                        System.out.println("Installed flow "+f+" in node "+ incoming_node);   	
	                    }else{
	                    System.out.println("output not found for IP = "+dstIP+" snapshot of the table"+this.ip_to_port_per_switch.toString()+" and "+this.ip_to_mac_destANDlocal.toString());
	                    }
	                }    
                }
           
         catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
            
        }
        return PacketResult.IGNORED;
    }
    
    
 
    
    ////ARP HANDLING//////
    protected void sendARPReply(NodeConnector p, byte[] sMAC, InetAddress sIP, byte[] tMAC, InetAddress tIP) {
        byte[] senderIP = sIP.getAddress();
        byte[] targetIP = tIP.getAddress();
        ARP arp = createARP(ARP.REPLY, sMAC, senderIP, tMAC, targetIP);

        Ethernet ethernet = createEthernet(sMAC, tMAC, arp);

        RawPacket destPkt = this.dataPacketService.encodeDataPacket(ethernet);
        destPkt.setOutgoingNodeConnector(p);

        this.dataPacketService.transmitDataPacket(destPkt);
        System.out.println("ARP reply sent to "+senderIP+" at MAC: "+sMAC+" saying that "+targetIP+" is at "+ tMAC);
    }

    private ARP createARP(short opCode, byte[] senderMacAddress, byte[] senderIP, byte[] targetMacAddress,
            byte[] targetIP) {
        ARP arp = new ARP();
        arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
        arp.setProtocolType(EtherTypes.IPv4.shortValue());
        arp.setHardwareAddressLength((byte) 6); 
        arp.setProtocolAddressLength((byte) 4); 
        arp.setOpCode(opCode);
        arp.setSenderHardwareAddress(senderMacAddress);
        arp.setSenderProtocolAddress(senderIP);
        arp.setTargetHardwareAddress(targetMacAddress);
        arp.setTargetProtocolAddress(targetIP);
        return arp;
    }   
    private Ethernet createEthernet(byte[] sourceMAC, byte[] targetMAC, ARP arp) {
        Ethernet ethernet = new Ethernet();
        ethernet.setSourceMACAddress(sourceMAC);
        ethernet.setDestinationMACAddress(targetMAC);
        ethernet.setEtherType(EtherTypes.ARP.shortValue());
        ethernet.setPayload(arp);
        return ethernet;
    }
    
    
   
}
