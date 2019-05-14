//LOAD BALANCER

//define counter
IF1_in, IF1_out, IF2_in, IF2_out :: AverageCounter; 
arp_req1, arp_rep1, ip1 :: Counter;
arp_req2, arp_rep2, ip2 :: Counter;
icmp, drop1, drop2, drop3 :: Counter;



// Traffic from server to client
init_server :: FromDevice(lb6-eth1, METHOD LINUX, SNIFFER false);
end_client :: Queue -> IF2_out -> ToDevice(lb6-eth2, METHOD LINUX); 

// Traffic from client to server
init_client :: FromDevice(lb6-eth2, METHOD LINUX, SNIFFER false);
end_server :: Queue -> IF1_out -> ToDevice(lb6-eth1, METHOD LINUX);


// Packet classification
client_pkt, server_pkt :: Classifier(
					12/0806 20/0001, //[0]ARP request
					12/0806 20/0002, //[1]ARP reply
					12/0800,	 //[2]IP
					-);		 //[3]others

	
// ARP querier
server_arpq :: ARPQuerier(100.0.0.25, lb6-eth1);
client_arpq :: ARPQuerier(100.0.0.25, lb6-eth2);


// IP packet
// GetIPAddress(16) OFFSET is usually 16, to fetch the destination address from an IP packet.

ip_to_client :: GetIPAddress(16) -> CheckIPHeader -> [0]client_arpq -> IPPrint("IP packet to client") -> end_client;
ip_to_server :: GetIPAddress(16) -> CheckIPHeader -> [0]server_arpq -> IPPrint("IP packet to server") -> end_server;


// round robin, IP rewrite
round_robin :: RoundRobinIPMapper(
	100.0.0.25 - 100.0.0.20 53 0 1, 
	100.0.0.25 - 100.0.0.21 53 0 1, 
	100.0.0.25 - 100.0.0.22 53 0 1);
ip_rewrite :: IPRewriter(round_robin, pattern 100.0.0.25 20000-65535 - -  1 0);
ip_rewrite[0] -> ip_to_server;
ip_rewrite[1] -> ip_to_client;


// packet from server 
init_server -> IF1_in -> server_pkt;
server_pkt[0] -> arp_req2 -> ARPResponder(100.0.0.25 lb6-eth1) -> end_server; //ARP request
server_pkt[1] -> arp_rep2 -> [1]server_arpq; //ARP reply

// Strip(14) to get rid of the Ethernet header

server_pkt[2] -> ip2 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet from server") -> [1]ip_rewrite; //IP packet
server_pkt[3] -> drop2 -> Discard; //Drop rest packet


// packet from client 
init_client -> IF2_in -> client_classifier;
client_pkt[0] -> arp_req1 -> ARPResponder(100.0.0.25 lb6-eth2) -> end_client; //ARP request
client_pkt[1] -> arp_rep1 -> [1]client_arpq; //ARP reply
client_pkt[2] -> ip1 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet from client") -> client_IP_pkt :: IPClassifier(icmp, dst udp port 53, -); //IP packet
	client_IP_pkt[0] -> icmp -> icmppr :: ICMPPingResponder() -> ip_to_client; //ICMP
	client_IP_pkt[1] -> [0]ip_rewrite; //UDP
	client_IP_pkt[2] -> drop3 -> Discard; //rest
client_pkt[3] -> drop1 -> Discard; //Drop rest packet


//Report
DriverManager(wait , print > ../results/lb1.report  "
	=================== LB1 Report ===================
	Input Packet Rate (pps): $(add $(IF2_in.rate) $(IF1_in.rate))
	Output Packet Rate(pps): $(add $(IF2_out.rate) $(IF1_out.rate))

	Total # of input packets: $(add $(IF2_in.count) $(IF1_in.count))
	Total # of output packets: $(add $(IF2_out.count) $(IF2_out.count))

	Total # of ARP requests packets: $(add $(arp_req1.count) $(arp_req2.count))
	Total # of ARP respondes packets: $(add $(arp_rep1.count) $(arp_rep2.count))

	Total # of service requests packets: $(add $(ip1.count) $(ip2.count))
	Total # of ICMP packets: $(icmp.count)
	Total # of dropped packets: $(add $(drop1.count) $(drop2.count) $(drop3.count))
	================================================== 
" , stop);