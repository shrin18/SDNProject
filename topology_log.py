#!/usr/bin/python
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, OVSLegacyKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, TCLink
from mininet.topo import Topo
from mininet.log import setLogLevel, info
import os
test_phase1 =os.path.expanduser('~') + '/ik2220-assign-phase1-team5/results/phase_1_report.txt'

def topology():
    "Create a network."
    net = Mininet( controller=RemoteController, link=TCLink, switch=OVSKernelSwitch )


    #begin controller
    c1 = net.addController( 'c1', controller=RemoteController, ip='127.0.0.1', port=6633, mac='00:00:00:00:00:0d' )

        #add switches
    print "*** Creating Switches"
    s1 = net.addSwitch( 's1', listenPort=6634, mac='00:00:00:00:00:02' )
    s2 = net.addSwitch( 's2', listenPort=6634, mac='00:00:00:00:00:03' )
    s3 = net.addSwitch( 's3', listenPort=6634, mac='00:00:00:00:00:04' )
    s4 = net.addSwitch( 's4', listenPort=6634, mac='00:00:00:00:00:05' )
    s5 = net.addSwitch( 's5', listenPort=6634, mac='00:00:00:00:00:06' )
    lb6 = net.addSwitch( 'lb6', listenPort=6634, mac='00:00:00:00:00:07' )
    lb7 = net.addSwitch( 'lb7', listenPort=6634, mac='00:00:00:00:00:08' )
    id8 = net.addSwitch( 'id8', listenPort=6634, mac='00:00:00:00:00:09' )
    n9 = net.addSwitch( 'n9',listenPort=6634, mac='00:00:00:00:00:0a' )
    fw10 = net.addSwitch ('fw10', listenPort = 6634, mac='00:00:00:00:00:0b')
    fw11 = net.addSwitch ('fw11' ,listenPort = 6634, mac='00:00:00:00:00:0c')

        #add hosts
    print "*** Creating Hosts "
    h1 = net.addHost( 'h1', ip='100.0.0.11/24' )
    h2 = net.addHost( 'h2', ip='100.0.0.12/24' )
    h3 = net.addHost( 'h3', ip='100.0.0.51/24' )
    h4 = net.addHost( 'h4', ip='100.0.0.52/24' )
    ws5 = net.addHost( 'ws5', ip='100.0.0.40/24' )
    ws6 = net.addHost( 'ws6', ip='100.0.0.41/24' )
    ws7 = net.addHost( 'ws7', ip='100.0.0.42/24' )
    ds8 = net.addHost( 'ds8', ip='100.0.0.20/24' )
    ds9 = net.addHost( 'ds9', ip='100.0.0.21/24' )
    ds10 = net.addHost( 'ds10', ip = '100.0.0.22/24')
    insp11 = net.addHost( 'insp11',ip = '100.0.0.30/24')




    print "*** Creating links"
    net.addLink(s1,h1)
    net.addLink(s1,h2)
    net.addLink(s1,fw10)
    net.addLink(s2,fw10)
    
    net.addLink(s2,fw11)
    net.addLink(s2,id8)
    net.addLink(s2,lb6)
    net.addLink(s3,ds8)
    net.addLink(s3,ds9)
    net.addLink(s3,ds10)
    net.addLink(s3,lb6)
    net.addLink(s4,ws5)
    net.addLink(s4,ws6)
    net.addLink(s4,ws7)
    net.addLink(s4,lb7)
    net.addLink(lb7,id8)
    net.addLink(n9,fw11)
    net.addLink(s5, h3)
    net.addLink(s5, h4)
    net.addLink(s5,n9)
    net.addLink(id8,insp11)

    print "*** Starting network"
    net.build()
    s1.start( [c1] )
    s2.start( [c1] )
    s3.start( [c1] )
    s4.start( [c1] )
    s5.start( [c1] )
    lb6.start( [c1] )
    lb7.start( [c1] )
    id8.start( [c1] )
    n9.start( [c1] )
    fw10.start( [c1] )
    fw11.start( [c1] )
    print ("Done")
    test_start(net)

def startserver(net):
    ds8 = net.get('ds8')
    ws5 = net.get('ws5')

    ds8.cmd('python3 dnsserver.py &')
    ws5.cmd('python -m SimpleHTTPServer 80 &')

def test_start(net):
    log = open(test_phase1, 'w+')
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    ds8 = net.get('ds8')
    ws5 = net.get('ws5')
    output = h1.cmdPrint('ping -c5', h2.IP())
    log.write('h1 ping h2\n'+output+'\n')

        #case 2
    output = h1.cmdPrint('ping -c5', h3.IP())
    log.write('h1 ping h3\n'+output+'\n')

        #case 3
    output = h1.cmdPrint('ping -c5', h4.IP())
    log.write('h1 ping h4\n'+output+'\n')

        #case4
    output = h3.cmdPrint('ping -c5', h4.IP())
    log.write('h3 ping h4\n'+output+'\n')

        #case5
    output = h3.cmdPrint('ping -c5', h1.IP())
    log.write('h3 ping h1\n'+output+'\n')

        #case6
    output = h3.cmdPrint('ping -c5', h2.IP())
    log.write('h3 ping h2\n'+output+'\n')

        #case7
    output = h1.cmdPrint('ping -c5', ds8.IP())
    log.write('h1 ping ds8\n'+output+'\n')

        #case8
    output = h1.cmdPrint('ping -c5', ws5.IP())
    log.write('h1 ping ws5\n'+output+'\n')

        #case9
    output = h2.cmdPrint('ping -c5', ws5.IP())
    log.write('h3 ping h1\n'+output+'\n')

        #case10
    output = h2.cmdPrint('ping -c5', ds8.IP())
    log.write('h2 ping ds8\n'+output+'\n')

        #case11
    output = h3.cmdPrint('ping -c5', ds8.IP())
    log.write('h3 ping ds8\n'+output+'\n')

        #case12
    output = h3.cmdPrint('ping -c5', ws5.IP())
    log.write('h3 ping ws5\n'+output+'\n')

        #case13
    output = h4.cmdPrint('ping -c5', ds8.IP())
    log.write('h4 ping ds8\n'+output+'\n')

        #case14
    output = h4.cmdPrint('ping -c5', ws5.IP())
    log.write('h4 ping ws5\n'+output+'\n')


    startserver(net)
    #15 UDP ds1
    dig = ''.join(['dig @', ds8.IP(), ' web1.com'])
    result=h3.cmdPrint(dig)
    log.write('h3 dig ds8\n'+result+'\n\n')
    
    #8 h1 UDP ds1
    dig = ''.join(['dig @', ds8.IP(), ' web1.com'])
    result=h1.cmdPrint(dig)
    log.write('h1 dig ds8\n'+result+'\n\n')

    
    log.close()

    #print "*** Running CLI"
    CLI( net )

    print "*** Stopping network"
    net.stop()

if __name__=='__main__':
        
        topology()
