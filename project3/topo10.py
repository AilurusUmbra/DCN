"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        sw1 = self.addSwitch( 'sw1' )
        sw2 = self.addSwitch( 'sw2' )
        sw3 = self.addSwitch( 'sw3' )
        sw4 = self.addSwitch( 'sw4' )
        
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        h4 = self.addHost( 'h4' )
        h5 = self.addHost( 'h5' )
        h6 = self.addHost( 'h6' )

        # Add links
        self.addLink( h1, sw1, bw=100 )
        self.addLink( h2, sw1, bw=100 )
        self.addLink( h3, sw2, bw=100 )
        self.addLink( h4, sw3, bw=100 )
        self.addLink( h5, sw4, bw=100 )
        self.addLink( h6, sw4, bw=100 )
        
        self.addLink( sw1, sw2, bw=1000 , loss=5 )
        self.addLink( sw3, sw2, bw=1000 , loss=5 )
        self.addLink( sw3, sw4, bw=1000 , loss=5 )



topos = { 'yourtopo': ( lambda: MyTopo() ) }
