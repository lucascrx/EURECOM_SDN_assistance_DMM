###Here is a quick sum up of the implementations we have:

* **RYU** : The controller is based on the code of simple_switch_13.py
  provided with the VM, the code has been improved in order to enable
  controller to handle first routing all among the network and then
  mobility.
  
*The controller is topology independent as long as the
  network respect the 2 following conditions : Strictly related
  backbone (each router must share a link with every other router) and
  the interface n°1 of each router must be dedicated to the local
  Network.*

 * **ODL**: The objective
  here is to implement a controller able to provide switches with
  router capabilities AND with mobility management capabilities.

* **MobilityModule** : is just a set of java class that formalize mobility
 management in SDN.

* **Topologies** is a folder where virtual networks are designed to test
  SDN controllers.

*Note June, 8:* Some big changes have finally occured, controller has
 been changed in order to make switch independant on the way their
 interfaces are configured : there is no more topology constrain
 related to switches' interfaces now. They can have several local
 interfaces in any order. Code has also been cleaned on tiny points
 (robustness). Report plan has then changed then some points has to be
 changed. 

Solved Issue : in inserting a third table in a symetric way as the
table n°0 it is now possible for switches to have multiple local
interfaces. It is also now possible for switches to relay ping
messages going to any interface of another switch.

Next Steps : finish and adapt the final report, continue code cleaning.
It would be nice to think about making controler working with a non
strictly related backbone : tunnel establishement seems to be the
tricky point of this enhancement.

*Note May, 28:* Subsequent tunneling has been made proper : now only
one tunnel is set up for a given direction between to given routers
then we avoid accumulating outdated tunnels. The tunnel updating has
been also modified in order to avoid subsequent updates of the same
tunnel when one node moves to a new network. As project is reaching
its end, from now progress will be less and less frequent...

Next steps: make the correspondent node moves also.

*Note May, 17:* Several Hops mobility is working as well as
loop over the network (when mobile node goes back to already visited
network), when the mobile node reaches a new network a new tunnel is
created between the current covering router and each old covering
router which is not really efficient as 4 flows are pushed for each
tunnel.

Solved Issue : when the user goes back to a already visited network,
instead of defining a tunnel which would be meaningless, the incoming
packet are simply transferred to the local interface.

Next Steps: consider other kinds of packets to handle than icmpv6,
discuss about the efficiency of the multi hops and looping handling
method; finish the writing the explication text. Think about make
mininet instruction list more handy to execute.

*Note May, 6:*Two flow tables are finally used : the first one is most
 of the time empty and miss entries are forwarded to the second one
 that is composed by the routing policies (routing flow triggered by
 pings are inserted in this table). When tunnels are set up to handle
 mobility the related actions as pushing/popping Vlan + forwarding to
 the second table are inserted in the first table. This way a packet
 can have its vlan tag stripped and being normally forwarded in being
 considered as a flow of the first table and subsequently as a flow of
 the second one.  Pinging between one host and a mobile one is now
 working!

 Solved Issues : using tables is proper than finding a way to loop back
 over the switch and enable to set flow proactively, then as some of
 the packets has to be transferred from the first table to the other,
 OFPinstructionGotoTable is defined and appended to the final
 instruction list.

 Next Step: handle properly subsequent hops across different networks,
 if possible handle the case when the user is back in its home
 network.  Clean code and write a simple user manual. Allow other
 message than ping messages

*Note May, 5:* Pushing Vlan troubles have been fixed, and now when an
 host moves from a router to another (in turning down and up ethernet
 interface and using MAC spoofing), ping packets from a third host are
 encapsulated in a new Vlan by the old router and transferred to the
 new one.

Solved Issues : the Vlan ID is written on 4 bits and has to set the
highest one to 1, then in our case an OR operation with 4096 is done
to get the final vlan value. The priority has also been raised.

Next Steps: being able to handle packets at the end of the tunnel with
a reactive flow setting. It could be nice to understand the meaning of
the OXM... header fields of open flow, that was the tricky point when
pushing Vlans. 


*Note April, 24:* Ping capabilities are still the same, the
code has been split into several functions. It's now possible to
generate the IPv6 address associated to a MAC address and a Network
prefix, tunnelling set up has been cleaned : but still problems on
MATCHS (apparently related to VLANs), 2 case out 4 may need to be
installed in a reactive mode instead of a proactive mode as we need
packet information for routing or setting up MAC addresses

 Solved Issues : as implementing node mobility with mininet seems
 quite complicated, a first solution is to create a static network
 consists in turning one of the host down while turning another host
 linked to another router up with the MAC address of the first
 host.

 Next Steps : Understanding how handle mobility with mininet in
 command line and not coded in the python configuration
 file. Resolving matching problems when setting up tunnels. Find a way
 to push the 2 problematic flow for tunnel establishment : may be
 implement reactive pushing.

*Note April, 19:* Hosts can ping each other across sub-networks and
can ping router local network interfaces. Backbone interfaces pinging
is not possible yet, is it really necessary to work on
it?...Controller keep trace of which host is under which router thanks
to neighbor advertisement, they are also able to respond to them to allow
mac address resolution. Ping routing is done by FLOWS installed in the different
switches that also updates MAC addresses.

Next Steps : Switch ping reply is still forwarded to controller, think
about pushing a new flow for it. Flows takes time to be set up : about
3 or 4 packets lost : thinking about buffering solution. Try to make
an host moves from one sub Network to another with mininet. Think
about handling exceptions in routing procedure.


*Note April, 17:* Now hosts can get configured autonomously, and
router can handle in addition neighbor solicitation and local ping,
but in every case messages go through the controller, no flow is set.
Code begins to get quite dirty, in the future it would be nice to
split it in modules. Instead of re-looping at tunnel ends it has been
decided to forward the packet on a default interface.

Solved Issues : Router should reply to Router Solicitation with its
Local Link address, make sure that it's the one set in the Router
Advertisements and not the global one.

Next Steps : enable controller with the handling of the other kind of
icmpv6 messages, think about when set up flows in the local router.

*Note April, 12:* finally in customizing the simple_router_13.py we
managed to get something that works: ipv6 seems to be handled by the
controller. Now our problem is to make mininet hosts consider Router
Advertisement Messages (their configuration seems ok). The formal
tunnelling model written in java has been integrated (simplified
version) but need to be tested.

Solved Issues : IP stacks of every interfaces of a given switch must
be configured in order to enable OpenFlow communication with this
switch and the controller, be sure to turn on interfaces with mininet
at the beginning.

Next steps : Enabling Stateless auto-configuration, Testing dmm, Enable
normal routing, discuss about MAC addresses in dmm.

*Note April, 7:* as lots of problems have been encountered with ryu
implementation and making it support ipv6, i push a little mobility
module that formalize the procedure in java

Next steps : finding solution to make either Ryu or ODL support ipv6

*Note mars, 30:* the controller is able to make routers enable
communications between 2 hosts that are directly linked to it.  

Next steps : > Handle sub domains : Routers discovery (ICMP packets?)
     	     > Enable multi switch management & configuration (HashMap)
