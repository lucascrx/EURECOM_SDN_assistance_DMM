Here is a quick sum up of the implementations we have:

*RYU : there is a router controller implementation written in the
 linux distribution of the VM distributed by SDN HUB, but currently
 our priority is to work with ODL.

*ODL: The objective here is to implement a controller able to provide
 switchs with router capabilities AND with mobility management
 capabilities.

Note april, 7: as lots of pb have been encountered with ryo
implementation and making it support ipv6, i push a little mobility
module that formalize the procedure in java

Next steps : finding solution to make either Ryu or ODL support ipv6

Note mars, 30 : the controller is able to make routers enable
communications between 2 hosts that are directly linked to it.  

Next steps : > Handle sub domains : Routers discovery (ICMP packets?)
     	     > Enable multi switch management & configuation (HashMap)
