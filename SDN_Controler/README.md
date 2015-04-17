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
