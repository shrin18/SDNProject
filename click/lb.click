IF1_in_1, IF1_out_1, IF2_in_1, IF2_out_1 :: AverageCounter; 
IF1_in_2, IF1_out_2, IF2_in_2, IF2_out_2 :: AverageCounter;

//define counters for different packets
arp_req1_1, arp_rep1_1, ip1_1 :: Counter;
arp_req2_1, arp_rep2_1, ip2_1 :: Counter;
icmp_1, drop_IF1_1, drop_IF2_1, drop_IP_1 :: Counter;
arp_req1_2, arp_rep1_2, ip1_2 :: Counter;
arp_req2_2, arp_rep2_2, ip2_2 :: Counter;
icmp_2, drop_IF1_2, drop_IF2_2, drop_IP_2 :: Counter;

// Traffic from server to client
init_serv_1 :: FromDevice(lb6-eth2, METHOD LINUX, SNIFFER false);
end_cli_1 :: Queue -> IF2_out_1 -> ToDevice(lb6-eth1, METHOD LINUX); 
init_serv_2 :: FromDevice(lb7-eth1, METHOD LINUX, SNIFFER false);
end_cli_2 :: Queue -> IF1_out_2 -> ToDevice(lb7-eth2, METHOD LINUX); 

// Traffic from client to server
init_cli_1 :: FromDevice(lb6-eth1, METHOD LINUX, SNIFFER false);
end_serv_1 :: Queue -> IF1_out_1 -> ToDevice(lb6-eth2, METHOD LINUX);
init_cli_2 :: FromDevice(lb7-eth2, METHOD LINUX, SNIFFER false);
end_serv_2 :: Queue -> IF2_out_2 -> ToDevice(lb7-eth1, METHOD LINUX);


// Packet classification
cli_pkt_1, serv_pkt_1 :: Classifier(
					12/0806 20/0001, //[0]ARP request
					12/0806 20/0002, //[1]ARP reply
					12/0800,	 //[2]IP
					-);		 //[3]others

cli_pkt_2, serv_pkt_2 :: Classifier(
					12/0806 20/0001, //[0]ARP request
					12/0806 20/0002, //[1]ARP reply
					12/0800,	 //[2]IP
					-);		 //[3]others

	
	
// ARP query definition
serv_arpq_1 :: ARPQuerier(100.0.0.25, lb6-eth2);
cli_arpq_1 :: ARPQuerier(100.0.0.25, lb6-eth1);	
serv_arpq_2 :: ARPQuerier(100.0.0.45, lb7-eth1);
cli_arpq_2 :: ARPQuerier(100.0.0.45, lb7-eth2);


// IP packet
// GetIPAddress(16) OFFSET is usually 16, to fetch the destination address from an IP packet.

ip_to_cli_1 :: GetIPAddress(16) -> CheckIPHeader -> [0]cli_arpq_1 -> IPPrint("IP packet destined to client") -> end_cli_1;
ip_to_serv_1 :: GetIPAddress(16) -> CheckIPHeader -> [0]serv_arpq_1 -> IPPrint("IP packet destined to server") -> end_serv_1;
ip_to_cli_2 :: GetIPAddress(16) -> CheckIPHeader -> [0]cli_arpq_2 -> IPPrint("IP packet destined to client") -> end_cli_2;
ip_to_serv_2 :: GetIPAddress(16) -> CheckIPHeader -> [0]serv_arpq_2 -> IPPrint("IP packet destined to server") -> end_serv_2;


// Load balancing through Round Rrobin and IP Rewrite elements
ip_map_1 :: RoundRobinIPMapper(
	100.0.0.25 - 100.0.0.20 53 0 1, 
	100.0.0.25 - 100.0.0.21 53 0 1, 
	100.0.0.25 - 100.0.0.22 53 0 1);
ip_assign_1 :: IPRewriter(ip_map_1, pattern 100.0.0.25 20000-65535 - -  1 0);
ip_assign_1[0] -> ip_to_serv_1;
ip_assign_1[1] -> ip_to_cli_1;

ip_map_2 :: RoundRobinIPMapper(
	100.0.0.45 - 100.0.0.40 80 0 1, 
	100.0.0.45 - 100.0.0.41 80 0 1, 
	100.0.0.45 - 100.0.0.42 80 0 1);
ip_assign_2 :: IPRewriter(ip_map_2, pattern 100.0.0.45 20000-65535 - -  1 0);
ip_assign_2[0] -> ip_to_serv_2;
ip_assign_2[1] -> ip_to_cli_2;


// packet coming from server 
init_serv_1 -> IF1_in_1 -> serv_pkt_1;
serv_pkt_1[0] -> arp_req2_1 -> ARPResponder(100.0.0.25 lb6-eth2) -> end_serv_1; 
serv_pkt_1[1] -> arp_rep2_1 -> [1]serv_arpq_1;
serv_pkt_1[2] -> ip2_1 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet coming from server") -> [1]ip_assign_1; //IP packet and Strip(14) to get rid of the Ethernet header
serv_pkt_1[3] -> drop_IF1_1 -> Discard; //Drop other packets

init_serv_2 -> IF2_in_2 -> serv_pkt_2;
serv_pkt_2[0] -> arp_req2_2 -> ARPResponder(100.0.0.45 lb7-eth1) -> end_serv_2; 
serv_pkt_2[1] -> arp_rep2_2 -> [1]serv_arpq_2;
serv_pkt_2[2] -> ip2_2 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet coming from server") -> [1]ip_assign_2; //IP packet and Strip(14) to get rid of the Ethernet header
serv_pkt_2[3] -> drop_IF2_2 -> Discard; //Drop other packets

// packet coming from client 
init_cli_1 -> IF2_in_1 -> cli_pkt_1;
cli_pkt_1[0] -> arp_req1_1 -> ARPResponder(100.0.0.25 lb6-eth1) -> end_cli_1; 
cli_pkt_1[1] -> arp_rep1_1 -> [1]cli_arpq_1; 
cli_pkt_1[2] -> ip1_1 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet coming from client") -> cli_IP_pkt_1 :: IPClassifier(icmp, dst udp port 53, -); //IP packet
	cli_IP_pkt_1[0] -> icmp_1 -> icmppr_1 :: ICMPPingResponder() -> ip_to_cli_1; //ICMP
	cli_IP_pkt_1[1] -> [0]ip_assign_1; //UDP
	cli_IP_pkt_1[2] -> drop_IP_1 -> Discard; //drop other IP packets
cli_pkt_1[3] -> drop_IF2_1 -> Discard; //Drop other packet

init_cli_2 -> IF1_in_2 -> cli_pkt_2;
cli_pkt_2[0] -> arp_req1_2 -> ARPResponder(100.0.0.45 lb7-eth2) -> end_cli_2; 
cli_pkt_2[1] -> arp_rep1_2-> [1]cli_arpq_2; 
cli_pkt_2[2] -> ip1_2 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet coming from client") -> cli_IP_pkt_2 :: IPClassifier(icmp, dst tcp port 80, -); //IP packet
	cli_IP_pkt_2[0] -> icmp_2 -> icmppr_2 :: ICMPPingResponder() -> ip_to_cli_2; //ICMP
	cli_IP_pkt_2[1] -> [0]ip_assign_2; //UDP
	cli_IP_pkt_2[2] -> drop_IP_2 -> Discard; //drop other IP packets
cli_pkt_2[3] -> drop_IF1_2 -> Discard; //Drop other packet



//Report generation

DriverManager(wait , print > lb.report  "
	=================== LB Report ===================================
	Input Packet Rate (pps): $(add $(IF2_in_1.rate) $(IF1_in_1.rate))
	Output Packet Rate(pps): $(add $(IF2_out_1.rate) $(IF1_out_1.rate))
	Input Packet Rate (pps): $(add $(IF2_in_2.rate) $(IF1_in_2.rate))
	Output Packet Rate(pps): $(add $(IF2_out_2.rate) $(IF1_out_2.rate))
	

	Total # of input packets: $(add $(IF2_in_1.count) $(IF1_in_1.count))
	Total # of output packets: $(add $(IF2_out_1.count) $(IF2_out_1.count))
	Total # of input packets: $(add $(IF2_in_2.count) $(IF1_in_2.count))
	Total # of output packets: $(add $(IF2_out_2.count) $(IF2_out_2.count))

	Total # of ARP requests packets: $(add $(arp_req1_1.count) $(arp_req2_1.count))
	Total # of ARP respondes packets: $(add $(arp_rep1_1.count) $(arp_rep2_1.count))
	Total # of ARP requests packets: $(add $(arp_req1_2.count) $(arp_req2_2.count))
	Total # of ARP respondes packets: $(add $(arp_rep1_2.count) $(arp_rep2_2.count))


	Total # of service requests packets: $(add $(ip1_1.count) $(ip2_1.count))
	Total # of ICMP packets: $(icmp_1.count)
	Total # of dropped packets: $(add $(drop_IF1_1.count) $(drop_IF2_1.count) $(drop_IP_1.count))

	Total # of service requests packets: $(add $(ip1_2.count) $(ip2_2.count))
	Total # of ICMP packets: $(icmp_2.count)
	Total # of dropped packets: $(add $(drop_IF1_2.count) $(drop_IF2_2.count) $(drop_IP_2.count))
	==================================================================== 
" , stop);
