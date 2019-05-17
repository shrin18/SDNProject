from pox.core import core
from pox.forwarding.l2_learning import LearningSwitch
from pox.lib.util import dpid_to_str
from firewall import firewall1, firewall2
from subprocess import Popen

log = core.getLogger()

path = "/opt/ik2220/pox/ext/"

class controller(object):
    def __init__(self):
        core.openflow.addListeners(self)
    
    def _handle_ConnectionUp(self,event):
        switch_id = dpid_to_str(event.dpid)
        print("Switch came up",switch_id)
        
        #Switches
        if (
            #Switch 1
            switch_id in "00-00-00-00-00-01"
            #Switch 2
            or switch_id in "00-00-00-00-00-02"
            #Switch 3
            or switch_id in "00-00-00-00-00-03"
            #Switch 4
            or switch_id in "00-00-00-00-00-04"
            #Switch 5
            or switch_id in "00-00-00-00-00-05"):
            print("Network entity is a switch",switch_id)
            LearningSwitch(event.connection,False)
            
        #Firewall 1
        elif switch_id in "00-00-00-00-00-15":
            print("Network entity is a Firewall Type 1",switch_id)
            firewall1(event.connection,False)
            
        #Firewall 2
        elif switch_id in "00-00-00-00-00-16":
            print("Network entity is a Firewall Type 2",switch_id)
            firewall2(event.connection,False)
            
        #Load balancer 1 for DNS servers
        elif switch_id in "00-00-00-00-00-0b":
            print("Network entity is Load balancer DNS Servers",switch_id)
            Popen(["click",path+"lb.click","Name=lb1","MAC0=03","port=53","proto=udp","MAC1=04","VIP=100.0.0.25","DIP0=100.0.0.20","DIP1=100.0.0.21","DIP2=100.0.0.22"])
            
        #Load balancer 2 for Web servers
        elif switch_id in "00-00-00-00-00-0c":
            print("Network entity is Load Balancer Web Servers",switch_id)
            Popen(["click",path+"lb.click","Name=lb2","MAC0=05","port=80","proto=tcp","MAC1=06","VIP=100.0.0.45","DIP0=100.0.0.40","DIP1=100.0.0.41","DIP2=100.0.0.42"])
            
        #IDS server
        elif switch_id in "00-00-00-00-00-0d":
            print("Network entity is IDS",switch_id)
            Popen(["click",path+"ids.click"])
            
        #NAPT
        elif switch_id in "00-00-00-00-00-1f":
            print("Network entity is NAPT",switch_id)
            Popen(["click",path+"napt.click"])
            
        #Unknown elements
        else:
            log.debug("Network entity is an unknown entity", switch_id)
            

    def _handle_ConnectionDown(self,event):
        print("Switch went down",dpid_to_str(event.dpid))

def launch():
    log.debug("Started")
    core.registerNew(controller)
