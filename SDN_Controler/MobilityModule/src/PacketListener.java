import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.HashMap;




public class PacketListener {
	
	//authentication module
	private AAAimplementation authModule;
	//Mobility Tracker Module
	private MobilityTracker mobTracker;
	
	/**
	 * ALSO NEED:
	 * TOPOLOGY MANAGER
	 * retrieving ipv6 @ from prefix + node_id 
	 * retrieving ipv6 @ from Node
	 * 
	 * **/
	
	
	private int counterTunnelID = 0;
	
	
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
						 * **/
						for (RouterPrefix ancester : trace){
							if(ancester.equals(trace.get(trace.size()-1))){
								break;//we are done
							}else{
								int tunnelID = this.counterTunnelID;
								this.counterTunnelID ++;
								
								//ANCESTER SIDE:
								
								//Flow Network ----> MN
								
								Match matchAncester1 = new Match();
								//computing old address of the node when it was under ancester coverage
								Inet6Address oldAddress = retrieveAddress(ancester.getPrefix(),newNodeID);
								matchAncester1.add('addr_nw_dest',oldAddress);
								
								Actions actionsAncester1 = new Actions();
								//this action doesn't exist
								actionAncester1.add(new Action('set_tunnel_id',counterTunnelID));
								actionAncester1.add(new Action('set_tunnel_dest',retrieveAddress(newRouter)));
								actionAncester1.add(new Action('Output',this.topologyManager.getInterface(ancester.getRouter(),newRouter)));
								Flow flowAncester1 = new flow(matchAncester1,actionAncester1);
								
								//Flow Network <---- MN
								
								Match matchAncester2 = new Match();
								matchAncester1.add('tunnel_id',counterTunnelID);
								
								Actions actionsAncester2 = new Actions();
								//this action doesn't exist
								actionsAncester2.add(new Action('unset_tunnel_id',counterTunnelID));
								//now the packet is like to the one that the mn sent when it was under ancester coverage
								//and the routing flow is already set : LOOPBACK
								actionsAncester2.add(new Action('Loopback'))
								Flow flowAncester2 = new flow(matchAncester2,actionAncester2);
								
								//pushing flows
								ancester.getRouter().pushflow(flowAncester1);
								ancester.getRouter().pushflow(flowAncester2);
								
								//NEW ROUTER SIDE
								
								//Flow Network <---- MN
								Match matchNewRouter1 = new Match();
								matchNewRouter1.add('addr_nw_src',oldAddress);
								
								Actions actionsNewRouter1 = new Actions();
								//this action doesn't exist
								actionNewRouter1.add(new Action('set_tunnel_id',counterTunnelID));
								actionAncester1.add(new Action('set_tunnel_dest',retrieveAddress(ancester.getRouter())));
								actionNewRouter1.add(new Action('Output',this.topologyManager.getInterface(newRouter,ancester.getRouter())));
								Flow flowNewRouter1 = new flow(matchNewRouter1,actionNewRouter1);
								
								//Flow Network ---> MN
								Match matchNewRouter2 = new Match();
								matchNewRouter2.add('tunnel_id',counterTunnelID);
								Actions actionsNewRouter2 = new Actions();
								//this action doesn't exist
								actionsNewRouter2.add(new Action('unset_tunnel_id',counterTunnelID));
								/**
								 * QUESTION: output on local interface  possible? as only edge routers
								 * **/
								Flow flowNewRouter2 = new flow(matchNewRouter2,actionNewRouter2);
								
								//pushing flows
								newRouter.pushflow(flowNewRouter1);
								newRouter.pushflow(flowNewRouter2);
	
							}
						}
							
					}
					
				}
				
			}
		}
		
	}

}
