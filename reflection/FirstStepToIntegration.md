#First Steps To Integration
----------------------------------------------------------------------

March 17, 

based on the reading of the article "Routing Optimization with SDN"
(Hyunsik Yang).

Let's imagine the network, entirely managed by a unique SDN
controller, flattened below:

	    +----+       +-------+	           
	    | CN |-------| CN-GW |
	    +----+	 +-------+
	    		    |
			    |
     +----------------------------------+
     |					|
     |	    SDN MANAGED NETWORK		|									|
     |	    				|
     +----------------------------------+
	|			|
	|			|
     +------+	            +-------+
     | GW-1 |	    	    | GW-2  |
     +------+	     	    +-------+
     			
	+----+
	| MN |   ------------>
	+----+

The MN (Mobile Node) is involved in a communication with CN
(Correspondent Node) through a SDN controlled network, (SDN controller
is not represented) and moves from GW-1 (where the IP address IP1 has
been assigned to it) to GW-2.

1st STEP :

When the MN performs the Handover, the GW-2 detects it and warns the
SDN Controller : this warning message must be part of the DMM protocol
over OpenFlow layer. The SDN then first learn to GW-2 how to handle
this new node (new IP address assignment: IP2...), and as it knows
that this node was belonging to GW-1 domain before, it triggers a
Mobility management procedure. (We can even imagine that the SDN
controller can knows if there active flows linked to the MN just
before he leaves GW-1, and then that he can decides whether or not
mobility has to be handled or not...) In this case the SDN Controller,
following the DMM protocol tells the GW-1 to redirect all the flows
destined to MN in a tunnel toward GW-2 that afterwards transfers
them to the MN (using PBU/PBA messages).  The flows set up after the
Handover don't need to go through the tunnel.

observation:

(+) Seems easy to handle packet loss during the handover, the GW-1 can
provide a temporary buffer which is then transmitted through the
tunnel.

(-) No Route optimization.

2nd STEP :

This step can be done in a second time but it's may be possible to
skip the first step, jumping directly to this one. The objective now
is to use the advantages provided by the SDN to get rid of the tunnel
between GW-1 and GW-2. The first idea would be to make the SDN
Controller updated the routing tables of all the network to make IP1
routed to GW2. This solution is cumbersome, not elegant and would make
routing tables blow up inside the network : CIDR effects would have
been lost...Then instead of warning each router of the network the SDN
controller can only tell the CN-GW to translate the destination
address of the outgoing packets belonging the "old flow" towards the MN
(the granularity of SDN controller's knowledge can be at a flow
level), in other terms IP1, to IP2. Then the packets will be routed
within the network to GW-2, which would have been told by the
controller to translate the destination address of the incoming
packets belonging to this flow (now it's IP2) to IP1. In the reverse
direction there is no need for address translation.

involve : 

-the SDN must have a way to specify a particular flow to the routers.
-routers then have to carry out a more complex treatment of packets.
-involve new DMM protocol messages.