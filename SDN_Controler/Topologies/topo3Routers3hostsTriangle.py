"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, RemoteController, Controller
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class MyTopo( Topo ):
    "Simple topology example."

    def build( self, **_opts ):
        "Create custom topo."

        # Add hosts and switches
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        
        switch1 = self.addSwitch( 's1' )
        switch2 = self.addSwitch( 's2' )
        switch3 = self.addSwitch( 's3' )

        self.addLink( host1, switch1 )
        self.addLink( host2, switch2 )
        self.addLink( host3, switch3 )


        # Add links
        self.addLink( switch1, switch2 )
        self.addLink( switch1, switch3 )
        self.addLink( switch3, switch2 )

def run():
    topo = MyTopo()
    net = Mininet(topo=topo, controller=RemoteController)
    s1, s2, s3 = net.get('s1','s2','s3')

    s1.cmd('ifconfig s1-eth1 inet6 add 2001::1/64')
    s1.cmd('ifconfig s1-eth2 inet6 add 2000:12::1/64')
    s1.cmd('ifconfig s1-eth3 inet6 add 2000:13::1/64')

    s2.cmd('ifconfig s2-eth1 inet6 add 2002::1/64')
    s2.cmd('ifconfig s2-eth2 inet6 add 2000:12::2/64')
    s2.cmd('ifconfig s2-eth3 inet6 add 2000:23::2/64')

    s3.cmd('ifconfig s3-eth1 inet6 add 2003::1/64')
    s3.cmd('ifconfig s3-eth2 inet6 add 2000:13::3/64')
    s3.cmd('ifconfig s3-eth3 inet6 add 2003:23::3/64')

    net.start()
    CLI(net)
    net.stop()
        
if __name__ == '__main__':
    setLogLevel( 'info' )
    run()

