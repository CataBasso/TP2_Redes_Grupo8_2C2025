# pox/ext/l2_learning_custom.py
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet

log = core.getLogger("l2_learning_custom")

# Tabla: dpid -> { MAC -> puerto }
mac_to_port = {}

def _handle_ConnectionUp(event):
    dpid = event.connection.dpid
    mac_to_port[dpid] = {}
    log.info("Switch %s connected", dpid)

def _handle_PacketIn(event):
    dpid = event.connection.dpid
    packet = event.parsed
    in_port = event.port

    if not packet:
        return
    if not isinstance(packet, ethernet):
        return

    src = packet.src
    dst = packet.dst

    # Aprender MAC de origen en este switch
    mac_to_port[dpid][src] = in_port
    log.debug("PacketIn at switch %s: src=%s dst=%s in_port=%s", dpid, src, dst, in_port)

    # Si conocemos la MAC destino, instalamos flujo hacia ese puerto
    if dst in mac_to_port[dpid]:
        out_port = mac_to_port[dpid][dst]
        fm = of.ofp_flow_mod()
        fm.match.dl_src = src
        fm.match.dl_dst = dst
        fm.match.in_port = in_port
        fm.actions.append(of.ofp_action_output(port=out_port))
        fm.idle_timeout = 30
        fm.hard_timeout = 60
        fm.data = event.ofp  # importante: reenvía el paquete actual
        event.connection.send(fm)
        log.info("Instalado flow en switch %s: %s -> %s (puerto %s)", dpid, src, dst, out_port)
    else:
        # Si no conocemos el destino, flood
        msg = of.ofp_packet_out(data=event.ofp)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = in_port
        event.connection.send(msg)
        log.debug("Flooding packet on switch %s", dpid)

def _handle_PortStatus(event):
    log.info("Port status change: %s", event)

def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.openflow.addListenerByName("PortStatus", _handle_PortStatus)
    log.info("l2_learning_custom cargado (con logging DEBUG en pox log.level)")
