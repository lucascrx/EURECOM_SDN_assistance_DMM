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
 handled. Indeed the controller, for each visited network, sets 2 pair
 of flows that define a VLAN oriented tunnel between the visited
 network gateway and the new covering gateway.  To enable a such
 mechanism 2 flow tables are pushed to switches, the first one contains
 the tunnelling mechanisms and the second one contains the routing
 flows.

2- How to use Ryu Controller
----------------------------

1. **Create the Network**:

Launch the mininet topology example file located [here](https://github.com/lucascrx/EURECOM_SDN_assistance_DMM/blob/master/SDN_Controler/Topologies/topo3Routers3hostsTriangle.py).

*COMMAND : $sudo python topo3Routers3hostsTriangle.py*

You can use your own mininet configuration file but be sure to have a
full related backbone and to set the interfaces number 1 of each
switch as the local network interface.


2. **Start Ryu Controller**

In parallel, start [ryu controller](https://github.com/lucascrx/EURECOM_SDN_assistance_DMM/blob/master/SDN_Controler/Ryu_framework/NewSimpleController.py),
don't forget options!  verbose can be cumbersome some times but for
it's still useful in the prototyping phase.
 
This controller uses an additional package :
[mobilityPackage](https://github.com/lucascrx/EURECOM_SDN_assistance_DMM/tree/master/SDN_Controler/Ryu_framework/mobilityPackage),
you have to install it also.

*COMMAND : $bin/ryu-manager --observe-link --verbose ryu/app/NewSimpleController.py*

3. **Configure default routes** 

From mininet console, for each host (in the example there are 3 hosts,
each linked to a different switch) configure its default route to the
local switch.

*COMMAND : mininet> h1 /sbin/route -A inet6 add default gw 2001::1*

	  *mininet> h2 /sbin/route -A inet6 add default gw 2002::1*

	  *mininet> h3 /sbin/route -A inet6 add default gw 2003::1*

4. **learn IP addresses**

From mininet console, learn what are the Global IPv6 addresses of the
hosts generated from the IPv6 auto-configuration procedure.

*COMMAND : mininet> h1 ifconfig*

5. **ping hosts** 

You can ping the address you have just learned from a given host

The first ping messages will be lost since no buffering mechanism is
set up. You can also ping switch's local network interface but not
their backbone interfaces

*COMMAND : mininet> h1 ping6 ..... *

6. **playing with mobility**

As no simple way with mininet prompt has been found to make an host
move from a switch to another, the idea is to trick mininet into make
it believe that h3 is h1. For that learn h1 MAC and IP address with
ifconfig, then configure h3 mac address with the one of h1 :

*COMMAND : mininet> ifconfig h3-eth0 down hw ... *

Then add the h1 previous IP address to h3 :

*COMMAND : mininet> ifconfig h3-eth0 inet6 add ... * 

set the h3-etg0 interface up again and don't forget to set up the
default route again.

Now if h2 pings h1 IP address h3 should reply and a vlan oriented
tunnel should take place between s1 and s3.