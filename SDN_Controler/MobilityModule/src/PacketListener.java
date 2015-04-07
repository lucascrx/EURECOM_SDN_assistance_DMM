import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.HashMap;




public class PacketListener {
	
	//authentication module
	private AAAimplementation authModule;
	//Mobility Tracker Module
	private MobilityTracker mobTracker;
	
	
	private int counterTunnelID = 0;
	
	/**
	 * ALSO NEED:
	 * TOPOLOGY MANAGER
	 * retrieving ipv6 @ from prefix + node_id 
	 * retrieving ipv6 @ from Node
	 * 
	 * :::
	 * 
	 * **/
	
	//TOPOLOGY manager
	private TopologyManager topologyManager;
	
	//provide the IPV6 of the provided Node
	public Inet6Address retrieveAddress(Node router){
		Inet6Address routerAddress = null;
		/**Consult a table**/
		return routerAddress;
	}
	
	//provide the IPV6 that the given host generates in a given network
	//Can be computed or may be using a storing table
	public Inet6Address retrieveAddress(Prefix netwPrefix, long nodeID){
		Inet6Address hostAddress = null;
		/**Computing**/
		return hostAddress;
	}
	
	/**sends openflow message to router containing flow f**/
	public void pushFlow(Flow f, Node Router){
		//TODO
	}
	
	
	
	void onPacketReceived(Node ReceivingNode, NodeConnector receivingIntf, Packet packet){
		
		//some stuff...
		if (packet instanceof ICMPV6){
			//We received an ICMPV6 packet
			ICMPV6 pck = (ICMPV6)packet;
			if(pck.getType()==ICMPV6.TYPE_ROUTER_SOLLICITATION){
			//This packet is a router sollicitation : fetching id of the sollicitating Node
				Long newNodeID = pck.getParamValue(ICMPV6.MN_IDENTIFIER);
				assert(newNodeID != null);
				//Fetching associated sub network Prefix from the AAA AND the authorization or not for handling mobility

				AuthenticationResponse response = this.authModule.register(newNodeID, ReceivingNode);
				if (response.getStatus()==AuthenticationResponse.POSITIVE){
					/**Now that we can handle mobility and that we have the prefix from 
					 * the Authentication Module, we can check if the new host comes
					 * from another sub-domain
					 * */
					Node newRouter = response.getNode();
					Prefix newPrefix = response.getSubNetPrefix();
					ArrayList<RouterPrefix> trace = this.mobTracker.getTraceAndUpdate(newNodeID, newRouter, newPrefix);
					
					if(trace.size()>1){//mobility tunnel have to be set up, otherwise nothing to do
						/**Tunnel Setting Up :
						 * (reverse tunnelling mode)
						 * for all router except the last one :
						 * 
						 * TUNNEL between router & the last one:
						 * 
						 * OLD ONE : >insert in the tunnel packets going to the MN
						 * 			 >extract from the tunnel packets from the MN inserted by the new router
						 * 
						 * NEW ONE : >extract from the tunnel packets to the MN inserted by the old router
						 * 			 >insert in the tunnel packets leaving from the MN
						 * 
						 * QUESTION: why not chainning tunnels with loopback?
						 * 
						 * **/
						for (RouterPrefix ancester : trace){
							if(ancester.equals(trace.get(trace.size()-1))){
								break;//we are done
							}else{
								int tunnelID = this.counterTunnelID;
								this.counterTunnelID ++;
								
								//ANCESTER SIDE:
								
								//Flow Network ----> MN
								
								Matchs matchAncester1 = new Matchs();
								//computing old address of the node when it was under ancester coverage
								Inet6Address oldAddress = retrieveAddress(ancester.getPrefix(),newNodeID);
								matchAncester1.add(new Match("addrNwDest",oldAddress));
								
								Actions actionsAncester1 = new Actions();
								//this action doesn't exist
								actionsAncester1.add(new Action("setTunnelId",counterTunnelID));
								actionsAncester1.add(new Action("setTunnelDest",retrieveAddress(newRouter)));
								actionsAncester1.add(new Action("Output",this.topologyManager.getInterface(ancester.getRouter(),newRouter)));
								Flow flowAncester1 = new Flow(matchAncester1,actionsAncester1);
								
								//Flow Network <---- MN
								
								Matchs matchAncester2 = new Matchs();
								matchAncester1.add(new Match("tunnelId",counterTunnelID));
								
								Actions actionsAncester2 = new Actions();
								//this action doesn't exist
								actionsAncester2.add(new Action("unsetTunnelId",counterTunnelID));
								//now the packet is like to the one that the mn sent when it was under ancester coverage
								//and the routing flow is already set : LOOPBACK
								actionsAncester2.add(new Action("loopback",null));
								Flow flowAncester2 = new Flow(matchAncester2,actionsAncester2);
								
								//pushing flows
								pushFlow(flowAncester1,ancester.getRouter());
								pushFlow(flowAncester2,ancester.getRouter());
								
								//NEW ROUTER SIDE
								
								//Flow Network <---- MN
								Matchs matchNewRouter1 = new Matchs();
								matchNewRouter1.add(new Match("addrNwSrc",oldAddress));
								
								Actions actionsNewRouter1 = new Actions();
								//this action doesn't exist
								actionsNewRouter1.add(new Action("setTunnelId",counterTunnelID));
								actionsNewRouter1.add(new Action("setTunnelDest",retrieveAddress(ancester.getRouter())));
								actionsNewRouter1.add(new Action("Output",this.topologyManager.getInterface(newRouter,ancester.getRouter())));
								Flow flowNewRouter1 = new Flow(matchNewRouter1,actionsNewRouter1);
								
								//Flow Network ---> MN
								Matchs matchNewRouter2 = new Matchs();
								matchNewRouter2.add(new Match("tunnelId",counterTunnelID));
								Actions actionsNewRouter2 = new Actions();
								//this action doesn't exist
								actionsNewRouter2.add(new Action("unsetTunnelId",counterTunnelID));
								/**
								 * QUESTION: output on local interface  possible? as only edge routers
								 * **/
								Flow flowNewRouter2 = new Flow(matchNewRouter2,actionsNewRouter2);
								
								//pushing flows
								pushFlow(flowNewRouter1,newRouter);
								pushFlow(flowNewRouter2,newRouter);
	
							}
						}
							
					}
					
				}
				
			}
		}
		
	}

}
