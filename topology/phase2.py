#!/usr/bin/python
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, OVSLegacyKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, TCLink
from mininet.topo import Topo
from mininet.log import setLogLevel, info
import os
test_phase1 =os.path.expanduser('/../results/Report_phase1')

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
    ds9 = net.get('ds9')
    ds10 = net.get('ds10')
    ws5 = net.get('ws5')
    ws6 = net.get('ws6')
    ws7 = net.get('ws7')
    


    ds8.cmd('python3 dns1.py &')
    ws5.cmd('python -m SimpleHTTPServer 80 &')
    ds9.cmd('python3 dns2.py &')
    ws6.cmd('python -m SimpleHTTPServer 80 &')
    ds10.cmd('python3 dns3.py &')
    ws7.cmd('python -m SimpleHTTPServer 80 &')

def test_start(net):
    log = open(test_phase1, 'w+')
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    ds8 = net.get('ds8')
    ws5 = net.get('ws5')
    insp11=net.get('insp11')
    ds8 = net.get('ds8')
    ds9 = net.get('ds9')
    ds10 = net.get('ds10')
    ws5 = net.get('ws5')
    ws6 = net.get('ws6')
    ws7 = net.get('ws7')

    insp11.cmd("tcpdump -s 0 -i insp11-eth0 -w insp11.pcap &")


        #case1 Ping within Public Zone
    output = h1.cmdPrint('ping -c5', h2.IP())
    log.write('Within Public Zone, ---h1 ping h2---\n'+output+'\n')

        #case 2 Ping Public to private zone
    output = h1.cmdPrint('ping -c5', h3.IP())
    log.write(' Public to Private Zone ---h1 ping h3---\n'+output+'\n')

        #case 3 Ping public to private
    output = h1.cmdPrint('ping -c5', h4.IP())
    log.write('Public to private ---h1 ping h4---\n'+output+'\n')

        #case4 Ping within Private zone
    output = h3.cmdPrint('ping -c5', h4.IP())
    log.write('Within Private Zone ---h3 ping h4---\n'+output+'\n')

        #case5 Private to public
    output = h3.cmdPrint('ping -c5', h1.IP())
    log.write('Private to Public ---h3 ping h1---\n'+output+'\n')

        #case6 Private to public
    output = h3.cmdPrint('ping -c5', h2.IP())
    log.write('Private to Public ---h3 ping h2---n'+output+'\n')

        #case7 Public to DMZ
    output = h1.cmdPrint('ping -c5', ds8.IP())
    log.write('Public to DMZ ---h1 ping ds8---\n'+output+'\n')

        #case8 Public to DMZ
    output = h1.cmdPrint('ping -c5', ws5.IP())
    log.write('Public to DMZ ---h1 ping ws5---\n'+output+'\n')

        #case9 Public to LB6
    output = h2.cmdPrint('ping -c5 100.0.0.25') 
    log.write('Public to DMZ ---h2 ping lb6---\n'+output+'\n')

        #case10 Public to lb7
    output = h2.cmdPrint('ping -c5 100.0.0.45')
    log.write('Public to DMZ ---h2 ping lb7---\n'+output+'\n')

        #case11 Private to DMZ
    output = h3.cmdPrint('ping -c5', ds8.IP())
    log.write('Private to DMZ ---h3 ping ds8---\n'+output+'\n')

        #case12 Private to DMZ
    output = h3.cmdPrint('ping -c5', ws5.IP())
    log.write('Private to DMZ ---h3 ping ws5---\n'+output+'\n')

        #case13 Private to lb6
    output = h4.cmdPrint('ping -c5 100.0.0.25')
    log.write('Private to DMZ ---h4 ping lb6---\n'+output+'\n')

        #case14 Private to LB7
    output = h4.cmdPrint('ping -c5 100.0.0.45')
    log.write('Private to DMZ ---h4 ping lb7---\n'+output+'\n')




    startserver(net)
    #15 h1 UDP lb6
    dig = ''.join(['dig @100.0.0.25 web1.com'])
    result=h1.cmdPrint(dig)
    log.write('h1 dig lb6\n'+result+'\n\n')

    #16 h2 UDP lb6
    dig = ''.join(['dig @100.0.0.25 web1.com'])
    result=h2.cmdPrint(dig)
    log.write('h2 dig lb6\n'+result+'\n\n')

    #17 h3 UDP lb6
    dig = ''.join(['dig @100.0.0.25 web2.com'])
    result=h3.cmdPrint(dig)
    log.write('h3 dig lb6\n'+result+'\n\n')

    #18 h4 UDP lb6
    dig = ''.join(['dig @100.0.0.25 web3.com'])
    result=h4.cmdPrint(dig)
    log.write('h4 dig lb6\n'+result+'\n\n')

    #19 h1 UDP ds8
    dig = ''.join(['dig +time=2 @', ds8.IP(), ' web1.com'])
    result=h1.cmdPrint(dig)
    log.write('h1 dig ds8\n'+result+'\n\n')
    
    #20 h1 UDP ds9
    dig = ''.join(['dig +time=2 @', ds9.IP(), ' web2.com'])
    result=h1.cmdPrint(dig)
    log.write('h1 dig ds9\n'+result+'\n\n')

    #21 h3 UDP ds10
    dig = ''.join(['dig +time=2 @', ds10.IP(), ' web3.com'])
    result=h3.cmdPrint(dig)
    log.write('h3 dig ds10\n'+result+'\n\n')



    #22 IDS test (h1 POST test)
    result = h1.cmdPrint('curl 100.0.0.45 -X POST')
    log.write('h1 POST test\n'+result+'\n\n')
    
    #23 IDS test (h2 PUT test)
    result = h3.cmdPrint('curl 100.0.0.45 -X PUT')
    log.write('h3 PUT test\n'+result+'\n\n')
    
    #24 IDS test (h3 GET test)
    result = h2.cmdPrint('curl -m 2 100.0.0.45 -X GET')
    log.write('h2 GET test\n'+result+'\n\n')
    
    #25 IDS test (h4 HEAD test)
    result = h4.cmdPrint('curl -m 2 HEAD 100.0.0.45')
    log.write('h4 HEAD test\n'+result+'\n\n')
    
    #26 IDS test (h1 OPTION test)
    result = h1.cmdPrint('curl -m 2 OPTION 100.0.0.45')
    log.write('h1 OPTION test\n'+result+'\n\n')
    
    #27 IDS test (h2 TRACE test)
    result = h3.cmdPrint('curl -m 2 -v -X TRACE 100.0.0.45')
    log.write('h3 TRACE test\n'+result+'\n\n')
    
    #28 IDS test (h3 DELETE test)
    result = h2.cmdPrint('curl -m 2 DELETE 100.0.0.45')
    log.write('h2 DELETE test\n'+result+'\n\n')
    
    #29 IDS test (h4 CONNECT test)
    result = h4.cmdPrint('curl -m 2 CONNECT 100.0.0.45')
    log.write('h4 CONNECT test\n'+result+'\n\n')

    #30 IDS test (h1 /etc/passwd test)
    result = h1.cmdPrint('curl -m 2 100.0.0.45 -X PUT -d "cat /etc/passwd"')
    log.write('h1 /etc/passwd test\n'+result+'\n\n')
    
    #31 IDS test (h3 /var/log/ test)
    result = h3.cmdPrint('curl -m 2 100.0.0.45 -X PUT -d "cat /var/log/"')
    log.write('h3 /var/log/ test\n'+result+'\n\n')
    
    #32 IDS test (h2 SQL INSERT test)
    result = h2.cmdPrint('curl -m 2 100.0.0.45 -X PUT -d "INSERT"')
    log.write('h2 INSERT test\n'+result+'\n\n')
    
    #33 IDS test (h4 SQL UPDATE test)
    result = h4.cmdPrint('curl -m 2 100.0.0.45 -X PUT -d "UPDATE"')
    log.write('h4 UPDATE test\n'+result+'\n\n')
    
    #34 IDS test (h1 SQL DELETE test)   
    result = h1.cmdPrint('curl -m 2 100.0.0.45 -X PUT -d "DELETE"')
    log.write('h1 DELETE test\n'+result+'\n\n')

    #35 h3 TCP ws1
    result=h3.cmdPrint('curl -m 2 ', ws5.IP())
    log.write('h3 curl ws1\n'+result+'\n\n')

    #36 h1 TCP ws1
    result=h1.cmdPrint('curl -m 2 ', ws6.IP())
    log.write('h1 curl ws1\n'+result+'\n\n')

    result=h1.cmdPrint('curl -m 2 ', ws7.IP())
    log.write('h1 curl ws7\n'+result+'\n\n')

    result=h1.cmdPrint('curl -m 2 ', ws8.IP())
    log.write('h1 curl ws8\n'+result+'\n\n')

    




    
    #17 h1 http
    # curl =''.join(['curl http://100.0.0.40:80/test.html'])
    # result= h1.cmdPrint(curl)
    # log.write('Server side running\n'+result+'\n\n')



 #   iperf = ''.join(['iperf -c 100.0.0.40  -n 1G -b 5M -p 80'])
 #   result= h1.cmdPrint(iperf)
 #   log.write('Server side running\n'+result+'\n\n')




    log.close()

    #print "*** Running CLI"
    CLI( net )

    print "*** Stopping network"
    net.stop()

if __name__=='__main__':

        topology()
