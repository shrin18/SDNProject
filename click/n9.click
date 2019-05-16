// define counter
counter_from_DmZ, counter_from_PrZ, counter_to_DmZ, counter_to_PrZ :: AverageCounter;
arp_req1, arp_res1, icmp1, ip1 :: Counter;
arp_req2, arp_res2, icmp2, ip2 :: Counter;
drop1, drop2, drop3, drop4 :: Counter;

AddressInfo(
	DmZ		100.0.0.1  	00:00:00:01:00:01,
	PrZ		10.0.0.1	00:00:00:00:10:01,
);


// DmZ to PrZ
from_DmZ :: FromDevice(n9-eth1, METHOD LINUX, SNIFFER false);
to_PrZ :: Queue -> counter_to_PrZ -> ToDevice(n9-eth2);


// PrZ to DmZ
from_PrZ :: FromDevice(n9-eth2, METHOD LINUX, SNIFFER false);
to_DmZ :: Queue -> counter_to_DmZ -> ToDevice(n9-eth1);


// Packet classifier
PrZ_classifier, DmZ_classifier :: Classifier(
	12/0806 20/0001, //[0]ARP request
	12/0806 20/0002, //[1]ARP reply
	12/0800, 		 //[2]IP
	-); 			 //[3]rest
	
	
// ARP querier
DmZ_arpq :: ARPQuerier(DmZ);
PrZ_arpq :: ARPQuerier(PrZ);


// IP packet
ip_to_DmZ :: GetIPAddress(16) -> CheckIPHeader -> [0]DmZ_arpq -> IPPrint("Ip packet to DmZ") -> to_DmZ;
ip_to_PrZ :: GetIPAddress(16) -> CheckIPHeader -> [0]PrZ_arpq -> IPPrint("Ip packet to PrZ") -> to_PrZ;


// TCP & UDP rewrite 
ip_rewrite :: IPRewriter(pattern 100.0.0.1 20000-65535 - - 0 1,drop);
ip_rewrite[0] -> ip_to_DmZ;
ip_rewrite[1] -> ip_to_PrZ;


// ICMP echo rewrite
icmp_rewrite :: ICMPPingRewriter(pattern 100.0.0.1 20000-65535 - - 0 1,drop);
icmp_rewrite[0] -> ip_to_DmZ;
icmp_rewrite[1] -> ip_to_PrZ;


// packet from DmZ
from_DmZ  -> counter_from_DmZ -> DmZ_classifier;
DmZ_classifier[0] -> arp_req1 -> ARPResponder(DmZ) -> to_DmZ; //ARP request
DmZ_classifier[1] -> arp_res1 -> [1]DmZ_arpq; //ARP reply
DmZ_classifier[2] -> ip1 -> Strip(14) -> CheckIPHeader -> IPPrint("IP packet from DmZ") -> DmZ_IP_classifier :: IPClassifier(icmp type echo-reply, udp or tcp, -); //IP packet
	DmZ_IP_classifier[0] -> icmp2 -> [1]icmp_rewrite;
	DmZ_IP_classifier[1] -> [1]ip_rewrite;
	DmZ_IP_classifier[2] -> drop3 -> Discard;
DmZ_classifier[3] -> drop1 -> Discard; //Drop rest packet


// packet from PrZ
from_PrZ -> counter_from_PrZ -> PrZ_classifier;
PrZ_classifier[0] -> arp_req2 -> ARPResponder(PrZ)-> to_PrZ; //ARP request
PrZ_classifier[1] -> arp_res2 -> [1]PrZ_arpq; //ARP reply
PrZ_classifier[2] -> ip2 -> Strip(14)-> CheckIPHeader -> IPPrint("IP packet from PrZ") -> PrZ_IP_classifier :: IPClassifier(icmp type echo, udp or tcp, -); //IP packet
	PrZ_IP_classifier[0] -> icmp1 -> [0]icmp_rewrite;
	PrZ_IP_classifier[1] -> [0]ip_rewrite;
	PrZ_IP_classifier[2] -> drop4 -> Discard;
PrZ_classifier[3] -> drop2 -> Discard; //Drop rest packet


// report
DriverManager(wait , print > n9.report "
	=================== NAPT Report ===================
	Input Packet Rate (pps): $(add $(counter_from_DmZ.rate) $(counter_from_PrZ.rate))
	Output Packet Rate(pps): $(add $(counter_to_DmZ.rate)  $(counter_to_PrZ.rate))

	Total # of input packets: $(add $(counter_from_DmZ.count) $(counter_from_PrZ.count))
	Total # of output packets: $(add $(counter_to_DmZ.count)  $(counter_to_PrZ.count))

	Total # of ARP requests packets: $(add $(arp_req1.count) $(arp_req2.count))
	Total # of ARP respondes packets: $(add $(arp_res1.count) $(arp_res2.count))

	Total # of service requests packets: $(add $(ip1.count) $(ip2.count))
	Total # of ICMP packets: $(add $(icmp1.count) $(icmp2.count))
	Total # of dropped packets: $(add $(drop1.count) $(drop2.count) $(drop3.count) $(drop4.count))
	================================================== 
" , stop);

