//Intrusion detection system
// Benign -> HTTP POST, PUT
// Malicious -> SQL injection  (cat /etc/passwd, cat /var/log/, INSERT, UPDATE, DELETE), 
//              HTTP GET, HEAD, OPTIONS, TRACE, DELETE, CONNECT
/*
+------ v ------+            +---------------+            +---------------+
|               |            |               |            |               |
|    SW2        |------------>     IDS       +----Benign-->    LB2        |
|               | fromSwitch |               |            |               |
+---------------+            +-------+-------+            +---------------+
                                     |
                                 Malicious
                                     |
                             +------ v ------+
                             |               |
                             |     INSP      |
                             |               |
                             +---------------+
*/

ctr_pkt_in, ctr_pkt_malicious, ctr_pkt_benign :: AverageCounter;

fromSwitch :: FromDevice(id8-eth1, METHOD LINUX, SNIFFER false);
fromLoadbal :: FromDevice(id8-eth2, METHOD LINUX, SNIFFER false);

toSwitch :: Queue -> ToDevice(id8-eth1); // connect sw2
toInsp :: Queue -> ctr_pkt_malicious -> ToDevice(id8-eth3); // connect insp and count number of malicious packets
toLoadbal :: Queue -> ctr_pkt_benign -> ToDevice(id8-eth2); // connect lb2 and count number of benign packets

//Define patterns to look out for
filter :: Classifier( 
	66/474554, // HTTP GET
	66/48454144, // HTTP head
	66/5452414345, // HTTP TRACE
	66/4f5054494f4e53, //HTTP OPTIONS
	66/44454c455445, //HTTP DELETE
	66/434f4e4e454354, //HTTP CONNECT
	209/636174202f6574632f706173737764, // "cat /etc/passwd"
	209/636174202f7661722f6c6f672f, // "cat /var/log/"
	208/494E53455254, //"INSERT"
	208/555044415445, //"UPDATE"
	208/44454C455445, //"DELETE"
	-); 


fromSwitch -> ctr_pkt_in -> filter; //  Count incoming pkts before sending to filter 

filter[0],filter[1],filter[2],filter[3],filter[4],filter[5],filter[6],filter[7],filter[8],filter[9],filter[10] -> toInsp;   // Send malicious pkts to Inspector

filter[11] -> toLoadbal;    //send all rest of the pkts(-) to loadbalancer2

fromLoadbal -> toSwitch;    // On return path ids should be transparant to all packets. Send all pkts from loadbalancer2 to sw2 


// report
DriverManager(wait , print >  $rPath/../results/ids.counter " #../results/ids.report
	=================== IDS Report ===================
	Input Packet Rate (pps): $(ctr_pkt_in.rate)
	Output Packet Rate(pps): $(ctr_pkt_benign.rate)
	Total # of input packets: $(ctr_pkt_in.count)
	Total # of output packets: $(ctr_pkt_benign.count)
	Total # of dropped packets: $(ctr_pkt_malicious.count)
	==================================================
" , stop);
