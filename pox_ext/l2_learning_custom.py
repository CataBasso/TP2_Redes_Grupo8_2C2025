# pox/ext/l2_learning_custom.py
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger("l2_learning_custom")

# tabla MAC -> (dpid, port)
mac_to_port = {}

def _handle_ConnectionUp(event):
    dpid = event.connection.dpid
    log.info("Switch %s connected", dpid)

def _handle_PacketIn(event):
    dpid = event.connection.dpid
    packet = event.parsed

    in_port = event.port

    # Seguridad: packet puede ser None
    if not packet:
        return

    # Sólo procesamos Ethernet
    if not isinstance(packet, ethernet):
        return

    src = packet.src
    dst = packet.dst

    # Aprendemos la MAC de origen
    mac_to_port[src] = (dpid, in_port)
    log.debug("PacketIn at switch %s: src=%s dst=%s in_port=%s", dpid, src, dst, in_port)
    log.debug("MAC table size: %d", len(mac_to_port))

    # Si conocemos la MAC destino y está en la misma dpid, instalar flujo
    if dst in mac_to_port:
        (dst_dpid, out_port) = mac_to_port[dst]
        if dst_dpid == dpid:
            # Instalar un flow en este switch
            fm = of.ofp_flow_mod()
            fm.match.dl_src = src
            fm.match.dl_dst = dst
            fm.match.in_port = in_port
            fm.actions.append(of.ofp_action_output(port=out_port))
            fm.idle_timeout = 30
            fm.hard_timeout = 60
            event.connection.send(fm)
            log.info("Instalado flow en switch %s: %s -> output:%s", dpid, dst, out_port)
            return

    # Si no sabemos a dónde enviar: flood
    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.in_port = in_port
    event.connection.send(msg)
    log.debug("Flooding packet on switch %s", dpid)

def _handle_PortStatus(event):
    log.info("Port status change: %s", event)

def launch():
    # Este launch se registra en POX
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.openflow.addListenerByName("PortStatus", _handle_PortStatus)
    log.info("l2_learning_custom cargado (con logging DEBUG en pox log.level)")
