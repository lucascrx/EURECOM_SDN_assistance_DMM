Here is a quick sum up of the implementations we have:

*RYU : there are now 2 router controller implementations both based on
 codes of linux distribution of the VM distributed by SDN HUB.  

 _the 1st one is from simple_switch_13.py and it's the code we are
 currently working on.

 _the 2nd one is from rest_router.py, we changed some setting of the
 rest interface but since it's quite complicated, we abandoned it.

*ODL: The objective here is to implement a controller able to provide
 switches with router capabilities AND with mobility management
 capabilities.

*MobilityModule : is just a set of java class that formalize mobility
 management in SDN.

* Topologies is a folder where virtual networks are designed to test
  SDN controllers.

Note April, 12: finally in customizing the simple_router_13.py we
managed to get something that works: ipv6 seems to be handled by the
controller. Now our problem is to make mininet hosts consider Router
Advertisement Messages (their configuration seems ok). The formal
tunnelling model written in java has been integrated (simplified
version) but need to be tested.

Next steps : Enabling Stateless autoconfiguration, Testing dmm, Enable
normal routing, discuss about MAC addresses in dmm.

Note April, 7: as lots of problems have been encountered with ryu
implementation and making it support ipv6, i push a little mobility
module that formalize the procedure in java

Next steps : finding solution to make either Ryu or ODL support ipv6

Note mars, 30 : the controller is able to make routers enable
communications between 2 hosts that are directly linked to it.  

Next steps : > Handle sub domains : Routers discovery (ICMP packets?)
     	     > Enable multi switch management & configuration (HashMap)
