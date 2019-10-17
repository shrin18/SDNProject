"""
Script created by POX custom flow generator (PCFG)
"""
from pox.core import core 
from pox.lib.addresses import IPAddr 
from pox.lib.addresses import EthAddr 
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

log = core.getLogger()

#flow0_0 Match structure
switch0=01
flow0_0msg = of.ofp_flow_mod()
flow1_0msg = of.ofp_flow_mod()
flow2_0msg = of.ofp_flow_mod()

#############################################
flow0_0msg.match.dl_type=0x800  #This matches packet as IPv4, if you do not use this further tp_src matches are ignored
flow0_0msg.match.in_port=1
flow0_0msg.match.nw_proto=pkt.ipv4.ICMP_PROTOCOL
flow0_0msg.match.tp_src = pkt.ICMP.TYPE_ECHO_REQUEST
#flow0_0msg.match.tp_src = pkt.ICMP.TYPE_ECHO_REPLY
flow1_0msg.match.dl_type=0x800  #This matches packet as IPv4, if you do not use this further tp_src matches are ignored
flow1_0msg.match.in_port=2
flow1_0msg.match.nw_proto=pkt.ipv4.ICMP_PROTOCOL
flow1_0msg.match.tp_src = pkt.ICMP.TYPE_ECHO_REQUEST
flow1_0msg.actions.append(of.ofp_action_output( port = 1 ) )
flow2_0msg.match.dl_type=0x800  #This matches packet as IPv4, if you do not use this further tp_src matches are ignored
flow2_0msg.match.in_port=1
flow2_0msg.match.nw_proto=pkt.ipv4.ICMP_PROTOCOL
#flow0_0msg.match.tp_src = pkt.ICMP.TYPE_ECHO_REQUEST
flow2_0msg.match.tp_src = pkt.ICMP.TYPE_ECHO_REPLY
flow2_0msg.actions.append(of.ofp_action_output( port = 2 ) )
###################################################


# ACTIONS----------------
flow0_0out = of.ofp_action_output(port =2)
#flow1_0out = of.ofp_action_output(port = 1)
#flow2_0out = of.ofp_action_output(port = 2)
flow0_0msg.actions=[flow0_0out]
#flow1_0msg.actions=[flow1_0out]
#flow2_0msg.actions=[flow2_0out]

def install_flows():
        log.info("  ### Installing static flows... ###")
        core.openflow.sendToDPID(switch0,flow0_0msg)
        core.openflow.sendToDPID(switch0,flow1_0msg)
        core.openflow.sendToDPID(switch0,flow2_0msg)
        log.info("### Static flows installed. ###")
def launch (): 
	log.info("####Starting...####")
	core.callDelayed (10, install_flows)
	log.info("### Waiting for switches to connect.. ###")
