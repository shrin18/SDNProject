//define counter
input1, output1, input2, output2 :: AverageCounter;
arp_req1, arp_res1, ip1 :: Counter;
arp_req2, arp_res2, ip2 :: Counter;
icmp, drop1, drop2, drop3 :: Counter;


//Define path
fromswitch2 :: FromDevice(lb6-eth1, METHOD LINUX, SNIFFER false);
fromswitch3 :: FromDevice(lb6-eth2, METHOD LINUX, SNIFFER false);
toswitch2 :: Queue -> output2 -> ToDevice(lb6-eth1, METHOD LINUX);
toswitch3 :: Queue -> output1 -> ToDevice(lb6-eth2, METHOD LINUX);

// Packet classifier
client_classifier, server_classifier :: Classifier(
                                            	12/0806 20/0001, //[0]ARP request
	                                            12/0806 20/0002, //[1]ARP reply
	                                                12/0800,		 //[2]IPpackets
	                                                  -);				 //[3]otherpackets

	
//Query packets for ARP
fromfirstswitch :: ARPQuerier(100.0.0.25, lb6-eth1);
fromotherswitch :: ARPQuerier(100.0.0.25, lb7-eth2);


// IP packet
iptoswitch2 :: GetIPAddress(16) -> CheckIPHeader -> [0]fromfirstswitch -> IPPrint("Ip packet to client") -> toswitch2;
iptoswitch3 :: GetIPAddress(16) -> CheckIPHeader -> [0]fromotherswitch -> IPPrint("Ip packet to server") -> toswitch3;


// round robin, IP rewrite
round_robin :: RoundRobinIPMapper(100.0.0.25 - 100.0.0.20 53 0 1, 100.0.0.25 - 100.0.0.21 53 0 1, 100.0.0.25 - 100.0.0.22 53 0 1);//Redirecting traffic to one of the servers
ip_rewrite :: IPRewriter(round_robin, pattern 100.0.0.25 20000-65535 - -  1 0);
ip_rewrite[0] -> iptoswitch2;
ip_rewrite[1] -> iptoswitch3;


// fromswitch2
fromswitch2 -> input2 -> server_classifier;
server_classifier[0] -> arp_req2 -> ARPResponder(100.0.0.25 lb6-eth1) -> toswitch2; //ARP request
server_classifier[1] -> arp_res2 -> [1]fromfirstswitch; //ARP reply
server_classifier[2] -> ip2 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet from server") -> [1]ip_rewrite; //IP packet
server_classifier[3] -> drop2 -> Discard; //Drop other packet


//fromswitch3
fromswitch3 -> input1 -> client_classifier;
client_classifier[0] -> arp_req1 -> ARPResponder(100.0.0.25 lb6-eth2) -> toswitch3; //ARP request
client_classifier[1] -> arp_res1 -> [1]fromotherswitch; //ARP reply
client_classifier[2] -> ip1 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet from client") -> client_IP_classifier :: IPClassifier(icmp, dst udp port 53, -); //IP packet
	client_IP_classifier[0] -> icmp -> icmppr :: ICMPPingResponder() -> iptoswitch2; //ICMP
	client_IP_classifier[1] -> [0]ip_rewrite; //UDP
	client_IP_classifier[2] -> drop3 -> Discard; //otherpackets
client_classifier[3] -> drop1 -> Discard; //Drop other packet


//Report
DriverManager(wait , print > ../results/lb1.report  "
	=================== LB1 Report ===================
	Input Packet Rate (pps): $(add $(input1.rate) $(input2.rate))
	Output Packet Rate(pps): $(add $(output1.rate) $(output2.rate))

	Total # of input packets: $(add $(input1.count) $(input2.count))
	Total # of output packets: $(add $(output1.count) $(output2.count))

	Total # of ARP requests packets: $(add $(arp_req1.count) $(arp_req2.count))
	Total # of ARP respondes packets: $(add $(arp_res1.count) $(arp_res2.count))

	Total # of service requests packets: $(add $(ip1.count) $(ip2.count))
	Total # of ICMP packets: $(icmp.count)
	Total # of dropped packets: $(add $(drop1.count) $(drop2.count) $(drop3.count))
	================================================== 
" , stop);	
