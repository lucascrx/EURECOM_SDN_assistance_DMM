### How to use Ryu Controller

1. **Create the Network**:

Launch the mininet topology example file located [here](https://github.com/lucascrx/EURECOM_SDN_assistance_DMM/blob/master/SDN_Controler/Topologies/topo3Routers3hostsTriangle.py).

*COMMAND : $sudo python topo3Routers3hostsTriangle.py *


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

*COMMAND : mininet> h1 /sbin/route -A inet6 add default gw 2001::1
	   mininet> h2 /sbin/route -A inet6 add default gw 2002::1
	   mininet> h3 /sbin/route -A inet6 add default gw 2003::1*

4. **learn IP addresses**

From mininet console, learn what are the Global IPv6 addresses of the
hosts generated from the IPv6 auto-configuration procedure.

*COMMAND : mininet> h1 ifconfig *

5. **ping hosts** 

You can ping the address you have just learned from a given host

The first ping messages will be lost since no buffering mechanism is
set up. You can also ping switch's local network interface but not
their backbone interfaces

*COMMAND : mininet> h1 ping6 <IPv6 address> *

