Some details about Ryu Controller 
=================================

1- How does the controller works? 
---------------------------------

* **PURPOSE** The goal is to build up an OpenFlow (1.3) Controller
 able to handle switches over a network, IPv6 oriented, divided in
 local sub-networks and a backbone in providing them basic routing
 skills and also the ability to manage hosts mobility across the
 network.  In a first time the only user data message considered over
 the network are ping messages

* **HOST CONFIGURATION** The controller enable switches to answer to
 router solicitation messages (sent from hosts when they are joining
 the network) with router advertisement messages that allows local
 hosts to get configured with the local prefix. It also enable them to
 learn from the neighbor solicitations messages which host is under
 their covering (the case of address conflict is not handled). In
 those cases no flow is pushed to the switch, router & neighbor
 solicitation are always transmitted to the controller that provides
 the router advertisement message and its output port.

* **ROUTING** The controller pushes re-actively flow to the switch
 that notices the reception of an unhandled ping packet, the forward
 actions associated to the flow are based on the ping message
 addresses. Switch are then able to route any message except the ones
 aiming backbones interfaces of others switches. Switches also answer
 to ping request with the help of the controller that provides them
 the reply without pushing any flow.

* **MOBILITY** the mobility of an host across the network is spotted
 out by the controller when the host send a router solicitation
 message to the destination switch and as the controller keeps track
 of every network it has visited before, mobility can be
 handled. Indeed the controller, for each visited network, sets 2 pairs
 of flows that define a VLAN oriented tunnel between the visited
 network gateway and the new covering gateway.  To enable a such
 mechanism 2 flow tables are pushed to switches, the first one contains
 the tunnelling mechanisms and the second one contains the routing
 flows.

2- Technical Details about tunnels and flows
--------------------------------------------

Let's consider a strictly related backbone network with 4 Routers,
each of them has a local interface that can host end node.  With this
topology let's assume a communication between a Correspondent Node
behind router 1 and a Mobile Node behind router 2 at the beginning.

* **Routing related flows**

When the Mobile Node hasn't moved yet from network 2 (ie the local
network associated to the router 2), every communication will be
carried out thanks to flows pushed to routers according to routing
algorithm in the SDN controller : all this flows pushed by the routing
intelligence take place on the 2nd flow table of each router which
default entry policy is to drop the packet. The *Match* component is
only based on the destination address and on the type of the ipv6
packet (it should be a "data" packet in the future) and the *Action*
component consists only in changing MAC addresses and forwarding the
packet on the right output port.  At this time the first flow table of
router 2 is empty but as the default entry policy is forwarding to the
second table, every packet is passed over it.

* **Moving to a different network**

When the Mobile Node moves from network 2 to network 3, the mobility
of the address it has forged in network 2 is ensured by a tunnelling
protocol between router 2 and router 3. Indeed the SDN controller
pushes two flows to the first table of router 2:

  * The first one matches packets coming from the network whose
  destination address is the one the Mobile Node forged when it was in
  network 2. The associated action is pushing a VLAN tag with a given
  value on those packets, changing MAC addresses and forwarding
  packets to router 3.

  * The second one matches packets coming directly from router 3 and
  encapsulated in a VLAN whose tag has the same value as the one used
  before. The first action consists in getting rid of the VLAN tag and
  then in relaying the new packet over the the second table so that it
  will be examined link a normal packet from the local network and be
  routed as usual to the external network.

Then two other flows are pushed to the first table of router 3:

  * The first one matches all the received packet on the local network
  interface whose source address is the one of the Mobile Node forged
  when it was in network 2. The associated action is to push a VLAN
  tag with the same value as before, to change MAC addresses and then
  to forward packets to router 2.

  * The second one matches packets from router 2 that include a VLAN
  tag with the same value as before. The associated action consists in
  popping VLAN tag, changing MAC addresses and forwarding packets on
  the local interface.

* **Subsequent handover** 

First it's important to know that the previous flows and the next ones
are pushed to routers as Flow Modification, that means that they are
written in a table if no similar flow is already inside but if not :
when there is an existing flow with the same matching properties in
the flow table, only action component will be used to update the one
of the existing flow.

Then if the Mobile Node after having gone through network 3, reaches
network 4, there are 2 address now for which mobility is handled the
one forged in network 3 and the older one forged in network 2.Then 2
new tunnels are established : one between router 4 and router 3 and
between and one router 4 and router 2 and the previously set up tunnel gets
obsolete. Therefore 2 new flow modification messages are pushed to
router 2, 2 new flow modification messages are pushed to router 3 and
2 times 2 new flow modifications messages are pushed to router 4
following exactly the same method as the single handover scenario.

On the 2 new flows pushed to router 2, the one matching packets coming
from the backbone has its matching component (which is packet
destination address equals to the address forged inside network 2)
that is the same as the one of the flow pushed when the mobile node
reached network 3 which is therefore updated with the action component
of the new pushed flow. Now all the packets coming to router 2 with
the address that the mobile node forged into network 2 as destination
address won't be anymore send in the tunnel linked to router 3 but in
the tunnel linked to router 4. The 3 others flow related to the tunnel
between router 2 and router 3 becomes useless and will be deleted
after a timeout.

* **Going back to a visited network**

When the mobile node is goes back to network 2 after having visited
network 3, new tunnels are set up between router 1 and router 2 and
between router3 and router 2 exactly as a subsequent handover. But
every packets that reaches router 2 from the backbone with destination
address equals to the address the Mobile Node has forged in network 2
are still send in a old tunnel to router 3 because they are matching
with the flow pushed to router 2 when the mobile node moved to network
3. To avoid this forwarding and get those packet delivered on the
network 2, an new flow is pushed to router 2 with the same matching
criteria as the old flow and overwrite its effect with an action
component set to forward packets on the local interface.

3- How to use Ryu Controller
----------------------------

**1. Create the Network**:

Launch the mininet topology example file located [here](https://github.com/lucascrx/EURECOM_SDN_assistance_DMM/blob/master/SDN_Controler/Topologies/topo3Routers3hostsTriangle.py).

       $sudo python topo3Routers3hostsTriangle.py

You can use your own mininet configuration file but be sure to have a
full related backbone and to set the interfaces number 1 of each
switch as the local network interface.


**2. Start Ryu Controller**

In parallel, start [ryu controller](https://github.com/lucascrx/EURECOM_SDN_assistance_DMM/blob/master/SDN_Controler/Ryu_framework/NewSimpleController.py),
don't forget options!  verbose can be cumbersome some times but for
it's still useful in the prototyping phase.
 
This controller uses an additional package :
[mobilityPackage](https://github.com/lucascrx/EURECOM_SDN_assistance_DMM/tree/master/SDN_Controler/Ryu_framework/mobilityPackage),
you have to install it also.

    	 $bin/ryu-manager --observe-link --verbose ryu/app/NewSimpleController.py

**3. Configure default routes** 

From mininet console, for each host (in the example there are 3 hosts,
each linked to a different switch) configure its default route to the
local switch.

	mininet> h1 /sbin/route -A inet6 add default gw 2001::1
	
	mininet> h2 /sbin/route -A inet6 add default gw 2002::1

	mininet> h3 /sbin/route -A inet6 add default gw 2003::1

**4. learn IP addresses**

From mininet console, learn what are the Global IPv6 addresses of the
hosts generated from the IPv6 auto-configuration procedure.

      	mininet> h1 ifconfig

**5. ping hosts** 

You can ping the address you have just learned from a given host

The first ping messages will be lost since no buffering mechanism is
set up. You can also ping switch's local network interface but not
their backbone interfaces

      mininet> h1 ping6 ..... 

**6. playing with mobility**

As no simple way with mininet prompt has been found to make an host
move from a switch to another, the idea is to trick mininet into make
it believe that h3 is h1. For that learn h1 MAC and IP address with
ifconfig, then configure h3 mac address with the one of h1 :
	  
      mininet> h3 ifconfig h3-eth0 down hw ether ... 

Then add the h1 previous IP address to h3 :

      mininet> h3 ifconfig h3-eth0 inet6 add ... 

set the h3-etg0 interface up again and don't forget to set up the
default route again.

      mininet> h3 ifconfig h3-eth0 up

Now if h2 pings h1 IP address h3 should reply and a vlan oriented
tunnel should take place between s1 and s3.