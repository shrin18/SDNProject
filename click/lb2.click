//LOAD BALANCER

//define average counters
IF1_in, IF1_out, IF2_in, IF2_out :: AverageCounter; 

//define counters for different packets
arp_req1, arp_rep1, ip1 :: Counter;
arp_req2, arp_rep2, ip2 :: Counter;
icmp, drop_IF1, drop_IF2, drop_IP :: Counter;

// Traffic from server to client
init_serv :: FromDevice(lb7-eth1, METHOD LINUX, SNIFFER false);
end_cli :: Queue -> IF1_out -> ToDevice(lb7-eth2, METHOD LINUX); 

// Traffic from client to server
init_cli :: FromDevice(lb7-eth2, METHOD LINUX, SNIFFER false);
end_serv :: Queue -> IF2_out -> ToDevice(lb7-eth1, METHOD LINUX);


// Packet classification
cli_pkt, serv_pkt :: Classifier(
					12/0806 20/0001, //[0]ARP request
					12/0806 20/0002, //[1]ARP reply
					12/0800,	 //[2]IP
					-);		 //[3]others

	
// ARP query definition
serv_arpq :: ARPQuerier(100.0.0.45, lb7-eth1);
cli_arpq :: ARPQuerier(100.0.0.45, lb7-eth2);


// IP packet
// GetIPAddress(16) OFFSET is usually 16, to fetch the destination address from an IP packet.

ip_to_cli :: GetIPAddress(16) -> CheckIPHeader -> [0]cli_arpq -> IPPrint("IP packet destined to client") -> end_cli;
ip_to_serv :: GetIPAddress(16) -> CheckIPHeader -> [0]serv_arpq -> IPPrint("IP packet destined to server") -> end_serv;


// Load balancing through Round Rrobin and IP Rewrite elements
ip_map :: RoundRobinIPMapper(
	100.0.0.45 - 100.0.0.40 80 0 1, 
	100.0.0.45 - 100.0.0.41 80 0 1, 
	100.0.0.45 - 100.0.0.42 80 0 1);
ip_assign :: IPRewriter(ip_map, pattern 100.0.0.45 20000-65535 - -  1 0);
ip_assign[0] -> ip_to_serv;
ip_assign[1] -> ip_to_cli;


// packet coming from server 
init_serv -> IF2_in -> serv_pkt;
serv_pkt[0] -> arp_req2 -> ARPResponder(100.0.0.45 lb7-eth1) -> end_serv; 
serv_pkt[1] -> arp_rep2 -> [1]serv_arpq;
serv_pkt[2] -> ip2 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet coming from server") -> [1]ip_assign; //IP packet and Strip(14) to get rid of the Ethernet header
serv_pkt[3] -> drop_IF2 -> Discard; //Drop other packets

// packet coming from client 
init_cli -> IF1_in -> cli_pkt;
cli_pkt[0] -> arp_req1 -> ARPResponder(100.0.0.45 lb7-eth2) -> end_cli; 
cli_pkt[1] -> arp_rep1 -> [1]cli_arpq; 
cli_pkt[2] -> ip1 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet coming from client") -> cli_IP_pkt :: IPClassifier(icmp, dst tcp port 80, -); //IP packet
	cli_IP_pkt[0] -> icmp -> icmppr :: ICMPPingResponder() -> ip_to_cli; //ICMP
	cli_IP_pkt[1] -> [0]ip_assign; //UDP
	cli_IP_pkt[2] -> drop_IP -> Discard; //drop other IP packets
cli_pkt[3] -> drop_IF1 -> Discard; //Drop other packet



//Report generation

DriverManager(wait , print > lb2.report  "
	=================== LB2 Report ===================================
	Input Packet Rate (pps): $(add $(IF2_in.rate) $(IF1_in.rate))
	Output Packet Rate(pps): $(add $(IF2_out.rate) $(IF1_out.rate))
	Total # of input packets: $(add $(IF2_in.count) $(IF1_in.count))
	Total # of output packets: $(add $(IF2_out.count) $(IF2_out.count))
	Total # of ARP requests packets: $(add $(arp_req1.count) $(arp_req2.count))
	Total # of ARP respondes packets: $(add $(arp_rep1.count) $(arp_rep2.count))
	Total # of service requests packets: $(add $(ip1.count) $(ip2.count))
	Total # of ICMP packets: $(icmp.count)
	Total # of dropped packets: $(add $(drop_IF1.count) $(drop_IF2.count) $(drop_IP.count))
	==================================================================== 
" , stop);

