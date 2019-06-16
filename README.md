[![Build Status](https://travis-ci.org/shrin18/SDN_Project.svg?branch=master)](https://travis-ci.org/shrin18/SDN_Project)

## SDN_Project

<img width="500" alt="topo" src="https://user-images.githubusercontent.com/23298265/58379578-ae2c9700-7fa5-11e9-80a6-9f4c0dfc71fa.PNG">

<p>This is a project based on the above topology which incorporates the use of Load Balanacer, Firewalls, Intrusion detecion system and the NAPT. The topology of this project is divided into three zones namely: Private, Public and DmZ. Stress Tests for the two firewalls are run by sending packets from one zone to the other. There are two sets of servers that are running a simpleHTTP and DNS server as configured in the dns.py scripts. Tests are also run for testing these servers using dig and curl commands respectively.</p>

<h3>Mininet Tutorial</h3>
https://kth.instructure.com/courses/7689/pages/ik2220-tutorial-video-mininet+pox?module_item_id=134779e

<h3>Visualiser</h3> http://mininet.spear.narmox.com
*Just paste your answer for links and dump in the given link and render graph for the topology for mininet*

<h3>Repo for VND (Visual Network Descriptor)</h3> https://github.com/ramonfontes/vnd
                            
                            
<h3>Commands for Starting topology, firewall, click scripts independently</h3>
<ol><strong>1. Topology</strong></ol>
<br>sudo python filename.py</br>
<ol><font size = "+15" ><strong>2. Firewall</strong></font></ol>
<br>./pox.py log.level --DEBUG forwarding.l2_firewall</br>
<ol><strong>3. Click</strong></ol>
<br>sudo /usr/local/bin/click filename.click</br>
