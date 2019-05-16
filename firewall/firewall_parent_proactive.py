# Copyright 2011-2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An L2 learning switch.
It is derived from one written live for an SDN crash course.
It is somwhat similar to NOX's pyswitch in that it installs
exact-match rules for each flow.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.addresses import IPAddr, EthAddr
import time
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

class FirewallSwitch (object):
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # Our firewall table
    self.firewall = {}

    # Add a Couple of Rules
    #self.AddRule('00-00-00-00-00-01',EthAddr('00:00:00:00:00:01'))
    #self.AddRule('00-00-00-00-00-01',EthAddr('00:00:00:00:00:02'))
    self.BasicRule(connection)
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))


  # function that allows adding firewall rules into the firewall table
  def AddRule (self, dpidstr, src=0,value=True):
    self.firewall[(dpidstr,src)]=value
    log.debug("Adding firewall rule in %s: %s", dpidstr, src)

  @classmethod
  def getConnection(self):
        return self.connection
  def BasicRule (self, connection):
    fm = of.ofp_flow_mod()
    fm.match.in_port = 1
    fm.priority = 18001
    fm.match.dl_type = 0x0806
    fm.actions.append(of.ofp_action_output( port = 2 ) )
    connection.send( fm )
    # Allow arp based on dl_type for in_port 2 to output 1
    fm = of.ofp_flow_mod()
    fm.match.in_port = 2
    fm.priority = 18001
    fm.match.dl_type = 0x0806
    fm.actions.append(of.ofp_action_output( port = 1 ) )
    connection.send( fm )
    # Default drop
    fm = of.ofp_flow_mod()
    fm.priority = 1001
    connection.send( fm )

  # function that allows deleting firewall rules from the firewall table
  # Not used DeleteRule
  def DeleteRule (self, dpidstr, src=0):
     try:
       del self.firewall[(dpidstr,src)]
       log.debug("Deleting firewall rule in %s: %s",
                 dpidstr, src)
     except KeyError:
       log.error("Cannot find in %s: %s",
                 dpidstr, src)


  # check if packet is compliant to rules before proceeding
  def CheckRule (self, dpidstr, src=0):
    try:
      entry = self.firewall[(dpidstr, src)]
      if (entry == True):
        log.debug("Rule (%s) found in %s: FORWARD",
                  src, dpidstr)
      else:
        log.debug("Rule (%s) found in %s: DROP",
                  src, dpidstr)
      return entry
    except KeyError:
      log.debug("Rule (%s) NOT found in %s: DROP",
                src, dpidstr)
      return False

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """

    packet = event.parsed

    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    # Get the DPID of the Switch Connection
    dpidstr = dpid_to_str(event.connection.dpid)

    packet = event.parsed
    if packet.type == packet.ARP_TYPE:
        log.info("Caught Arp packet")

    # Check the Firewall Rules
    if self.CheckRule(dpidstr, packet.src) == False:
      drop()
      return

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)


class firewall (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    #FirewallSwitch(event.connection, self.transparent)
    log.debug("###################DPID#############:%s ", dpid_to_str(event.connection.dpid))
    # Allow arp based on dl_type for in_port 1 to output 2
    #if dpid_to_str(event.connection.dpid) == "00-00-00-00-00-01":
#       return
    if dpid_to_str(event.connection.dpid) == "00-00-00-00-00-0a":
        fw1 = FW1(event.connection, self.transparent)
        fw1.AddRule(event.connection)
    elif dpid_to_str(event.connection.dpid) == "00-00-00-00-00-0b":
        fw2 = FW2(event.connection, self.transparent)
        fw2.AddRule(event.connection)
    else:
        return

class FW1 (FirewallSwitch):
    @staticmethod
    def AddRule(connection):
        #connection = connection()
        # ICMP Echo Request in_port 2 out_port 1
        fm = of.ofp_flow_mod()
        fm.match.in_port = 2
        fm.priority = 33001
        fm.match.dl_type = 0x0800
        fm.match.nw_proto=pkt.ipv4.ICMP_PROTOCOL
        fm.match.tp_src = pkt.ICMP.TYPE_ECHO_REQUEST
        fm.actions.append(of.ofp_action_output( port = 1 ) )
        connection.send( fm )
        # ICMP Echo Reply in_port 1 out_port 2
        fm = of.ofp_flow_mod()
        fm.match.in_port = 1
        fm.priority = 33001
        fm.match.dl_type = 0x0800
        fm.match.nw_proto=pkt.ipv4.ICMP_PROTOCOL
        fm.match.tp_src = pkt.ICMP.TYPE_ECHO_REPLY
        fm.actions.append(of.ofp_action_output( port = 2 ) )
        connection.send( fm )

class FW2 (FirewallSwitch):
    @staticmethod
    def AddRule(connection):
        # ALLOW default in_port 2 out_port 1
        fm = of.ofp_flow_mod()
        fm.match.in_port = 2
        fm.priority = 33001
        #fm.match.dl_type = 0x0800
        #fm.match.nw_proto=pkt.ipv4.ICMP_PROTOCOL
        #fm.match.tp_src = pkt.ICMP.TYPE_ECHO_REQUEST
        fm.actions.append(of.ofp_action_output( port = 1 ) )
        connection.send( fm )
        # Allow Echo Reply in_port 1 out_port 2
        fm = of.ofp_flow_mod()
        fm.match.in_port = 1
        fm.priority = 33001
        fm.match.dl_type = 0x0800
        fm.match.nw_proto=pkt.ipv4.ICMP_PROTOCOL
        fm.match.tp_src = pkt.ICMP.TYPE_ECHO_REPLY
        fm.actions.append(of.ofp_action_output( port = 2 ) )
        connection.send( fm )

def launch (transparent=False, hold_down=_flood_delay):
  """
  Starts an firewall switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(firewall, str_to_bool(transparent))
