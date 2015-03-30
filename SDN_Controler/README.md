Here is a quick sum up of the implementations we have:

*RYO : there is a router controller implementation written in the
 linux distribution of the VM distributed by SDN HUB, but currently
 our priority is to work with ODL.

*ODL: The objective here is to implement a controller able to provide
 switchs with router capabilities AND with mobility management
 capabilities.

Note mars, 30 : the controller is able to make routers enable
communications between 2 hosts that are directly linked to it.  

Next steps : > Handle sub domains : Routers discovery (ICMP packets?)
     	     > Enable multi switch management & configuation (HashMap)
