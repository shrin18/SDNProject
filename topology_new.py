#!/usr/bin/python

"""
Script created by VND - Visual Network Description (SDN version)
"""
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, OVSLegacyKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, TCLink

def topology():
    "Create a network."
    net = Mininet( controller=RemoteController, link=TCLink, switch=OVSKernelSwitch )

    print "*** Creating nodes"
    c1 = net.addController( 'c1', controller=RemoteController, ip='127.0.0.1', port=6633 )
    s1 = net.addSwitch( 's1', listenPort=6634 )
    s2 = net.addSwitch( 's2', listenPort=6634 )
    s3 = net.addSwitch( 's3', listenPort=6634 )
    s4 = net.addSwitch( 's4', listenPort=6634 )
    s5 = net.addSwitch( 's5', listenPort=6634 )
    lb1 = net.addSwitch( 'lb1', listenPort=6634 )
    lb2 = net.addSwitch( 'lb2', listenPort=6634 )
    id1 = net.addSwitch( 'id1', listenPort=6634 )
    n1 = net.addSwitch( 'n1',listenPort=6634 )
    fw1 = net.addSwitch ('fw1', listenPort = 6634)
    fw2 = net.addSwitch ('fw2' ,listenPort = 6634)
    h1 = net.addHost( 'h1', ip='100.0.0.11/24' )
    h2 = net.addHost( 'h2', ip='100.0.0.12/24' )
    h3 = net.addHost( 'h3', ip='100.0.0.51/24' )
    h4 = net.addHost( 'h4', ip='100.0.0.52/24' )
    ws1 = net.addHost( 'ws1', ip='100.0.0.40/24' )
    ws2 = net.addHost( 'ws2', ip='100.0.0.41/24' )
    ws3 = net.addHost( 'ws3', ip='100.0.0.42/24' )
    ds1 = net.addHost( 'ds1', ip='100.0.0.20/24' )
    ds2 = net.addHost( 'ds2', ip='100.0.0.21/24' )
    ds3 = net.addHost( 'ds3', ip = '100.0.0.22/24')
    insp1 = net.addHost( 'insp1',ip = '100.0.0.30/24')

    print "*** Creating links"
    net.addLink(s1,h1)
    net.addLink(s1,h2)
    net.addLink(s1,fw1)
    net.addLink(s2,fw1)
    
    net.addLink(s2,fw2)
    net.addLink(s2,id1)
    net.addLink(s2,lb1)
    net.addLink(s3,ds1)
    net.addLink(s3,ds2)
    net.addLink(s3,ds3)
    net.addLink(s3,lb1)
    net.addLink(s4,ws1)
    net.addLink(s4,ws2)
    net.addLink(s4,ws3)
    net.addLink(s4,lb2)
    net.addLink(lb2,id1)
    net.addLink(n1,fw2)
    net.addLink(s5, h3)
    net.addLink(s5, h4)
    net.addLink(s5,n1)
    net.addLink(id1,insp1)

    print "*** Starting network"
    net.build()
    s1.start( [c1] )
    s2.start( [c1] )
    s3.start( [c1] )
    s4.start( [c1] )
    s5.start( [c1] )
    lb1.start( [c1] )
    lb2.start( [c1] )
    id1.start( [c1] )
    n1.start( [c1] )
    fw1.start( [c1] )
    fw2.start( [c1] )
    print ("Done")

    print "*** Running CLI"
    CLI( net )

    print "*** Stopping network"
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()
