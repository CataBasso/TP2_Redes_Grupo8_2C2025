# pox/ext/l2_learning_custom.py
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
import pox.lib.packet as pkt
import json
import os
import signal

log = core.getLogger("l2_learning_custom")

mac_to_port = {}
switch_names = {}
switch_counter = 0
firewall_config = None
firewall_switch_dpid = None
firewall_flows_installed = set()  # Track installed firewall flows to avoid duplicates

def reset_switch_counter():
    """
    Reinicia el contador de switches y limpia los nombres.
    """
    global switch_counter, switch_names, firewall_flows_installed
    switch_counter = 0
    switch_names = {}
    firewall_flows_installed = set()

def reset_state():
    """
    Resetea todo el estado en memoria del módulo: tablas de aprendizaje,
    mapeos host<->mac, contadores y flows instalados.

    Esto permite ejecutar tests repetidos sin reiniciar el proceso POX.
    """
    global mac_to_port, switch_names, switch_counter, host_to_mac, mac_to_host, firewall_flows_installed
    mac_to_port = {}
    switch_names = {}
    switch_counter = 0
    host_to_mac = {"h1": None, "h2": None, "h3": None, "h4": None}
    mac_to_host = {}
    firewall_flows_installed = set()
    log.info("l2_learning_custom: Estado interno reseteado (reset_state)")

host_to_mac = {
    "h1": None,
    "h2": None,
    "h3": None,
    "h4": None
}

mac_to_host = {}

def load_firewall_config():
    """
    Carga la configuración del firewall desde el archivo JSON.
    
    Busca el archivo firewall_rules.json en el directorio raíz del proyecto
    y carga las reglas del firewall. Si el archivo no existe o hay un error
    al parsearlo, el firewall queda deshabilitado.
    """
    global firewall_config, firewall_switch_dpid
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    config_path = os.path.join(project_root, "firewall_rules.json")
    
    try:
        with open(config_path, 'r') as f:
            firewall_config = json.load(f)
        
        firewall_switch_name = firewall_config.get("firewall_switch", "s2")
        log.info("Firewall configurado para switch: %s", firewall_switch_name)
        log.info("Reglas cargadas: %d", len(firewall_config.get("rules", [])))
        
    except FileNotFoundError:
        log.warning("No se encontró firewall_rules.json, firewall deshabilitado")
        firewall_config = None
    except json.JSONDecodeError as e:
        log.error("Error al parsear firewall_rules.json: %s", e)
        firewall_config = None

def is_firewall_switch(dpid):
    """
    Verifica si el switch con el dpid dado es el switch del firewall.
    
    Args:
        dpid: El identificador del switch (datapath ID)
    
    Returns:
        True si el switch es el firewall, False en caso contrario
    """
    if firewall_config is None:
        return False
    
    firewall_switch_name = firewall_config.get("firewall_switch", "s2")
    switch_name = switch_names.get(dpid)
    
    log.debug("FIREWALL: Verificando switch - dpid=%s, switch_name=%s, firewall_switch=%s", 
             dpid, switch_name, firewall_switch_name)
    
    if switch_name == firewall_switch_name:
        return True
    return False

def get_host_from_mac(mac):
    """
    Obtiene el nombre del host (h1, h2, etc.) a partir de su MAC.
    
    Args:
        mac: Dirección MAC del host
    
    Returns:
        Nombre del host (h1, h2, h3, h4) o None si no se conoce
    """
    return mac_to_host.get(mac)

def learn_host_mac(mac, host_name):
    """
    Aprende la MAC de un host y actualiza las tablas de mapeo.
    
    Args:
        mac: Dirección MAC del host
        host_name: Nombre del host (h1, h2, h3, h4)
    """
    if host_name in host_to_mac:
        old_mac = host_to_mac[host_name]
        if old_mac != mac:
            if old_mac and old_mac in mac_to_host:
                del mac_to_host[old_mac]
        host_to_mac[host_name] = mac
        mac_to_host[mac] = host_name
        log.info("Aprendido: %s -> %s", host_name, mac)

def check_firewall_rules(packet, src_mac, dst_mac, dpid):
    """
    Verifica si un paquete debe ser bloqueado por las reglas del firewall.

    Retorna:
        La regla (dict) que matchea, o None si no coincide ninguna.
    """
    if firewall_config is None:
        return None

    if not is_firewall_switch(dpid):
        return None

    log.info("FIREWALL: Verificando reglas en switch %s (dpid=%s)", switch_names.get(dpid, dpid), dpid)

    rules = firewall_config.get("rules", [])

    ipv4p = packet.find('ipv4')
    ipv6p = packet.find('ipv6')
    if not ipv4p and not ipv6p:
        log.debug("FIREWALL: Paquete no es IPv4 ni IPv6")
        return None

    if ipv4p:
        src_ip = str(ipv4p.srcip)
        dst_ip = str(ipv4p.dstip)
    elif ipv6p:
        src_ip = str(ipv6p.srcip)
        dst_ip = str(ipv6p.dstip)

    log.info("FIREWALL: Paquete IP - src=%s dst=%s", src_ip, dst_ip)

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        rule_type = rule.get("type")

        if rule_type == "port_block":
            dst_port = rule.get("dst_port")
            if dst_port:
                tcpp = packet.find('tcp')
                udpp = packet.find('udp')
                if tcpp and tcpp.parsed and tcpp.dstport == dst_port:
                    log.warning("FIREWALL: Regla port_block coincide (TCP) id=%s port=%s", rule.get("id"), dst_port)
                    return rule
                if udpp and udpp.parsed and udpp.dstport == dst_port:
                    log.warning("FIREWALL: Regla port_block coincide (UDP) id=%s port=%s", rule.get("id"), dst_port)
                    return rule

        if rule_type == "host_port_protocol_block":
            src_host = rule.get("src_host")
            dst_port = rule.get("dst_port")
            protocol = rule.get("protocol", "").upper()

            if src_host and dst_port:
                src_host_actual = get_host_from_mac(src_mac)
                log.debug("FIREWALL: Regla host_port_protocol - src_host_actual=%s, src_host=%s, protocol=%s, dst_port=%s",
                          src_host_actual, src_host, protocol, dst_port)
                if src_host_actual == src_host:
                    if protocol == "UDP":
                        udpp = packet.find('udp')
                        if udpp and udpp.parsed and udpp.dstport == dst_port:
                            log.warning("FIREWALL: Regla host_port_protocol_block coincide (UDP) id=%s", rule.get("id"))
                            return rule
                    elif protocol == "TCP":
                        tcpp = packet.find('tcp')
                        if tcpp and tcpp.parsed and tcpp.dstport == dst_port:
                            log.warning("FIREWALL: Regla host_port_protocol_block coincide (TCP) id=%s", rule.get("id"))
                            return rule

        if rule_type == "host_pair_block":
            host1 = rule.get("host1")
            host2 = rule.get("host2")
            if host1 and host2:
                src_host = get_host_from_mac(src_mac)
                dst_host = get_host_from_mac(dst_mac)
                log.debug("FIREWALL: Verificando regla host_pair - src_host=%s, dst_host=%s, host1=%s, host2=%s",
                          src_host, dst_host, host1, host2)
                if (src_host == host1 and dst_host == host2) or (src_host == host2 and dst_host == host1):
                    log.warning("FIREWALL: Regla host_pair_block coincide id=%s", rule.get("id"))
                    return rule

    return None

def _handle_ConnectionUp(event):
    """
    Maneja el evento de conexión de un switch al controlador.
    
    Inicializa la tabla de aprendizaje para el switch, le asigna un nombre
    basado en el orden de conexión (s1, s2, etc.) y verifica si es el switch
    del firewall.
    
    Args:
        event: Evento de conexión del switch
    """
    global switch_counter
    dpid = event.connection.dpid
    mac_to_port[dpid] = {}
    
    switch_counter += 1
    switch_name = f"s{switch_counter}"
    switch_names[dpid] = switch_name
    
    log.info("Switch %s (dpid=%s) connected", switch_name, dpid)
    
    if is_firewall_switch(dpid):
        log.info("*** Este switch (%s) es el FIREWALL ***", switch_name)

def _handle_PacketIn(event):
    """
    Maneja los paquetes que llegan al controlador sin matching flow.
    
    Aprende las MACs de los hosts, verifica las reglas del firewall,
    y instala flows de forwarding o descarte según corresponda.
    
    Args:
        event: Evento PacketIn del switch
    """
    dpid = event.connection.dpid
    packet = event.parsed
    in_port = event.port

    if not packet:
        return
    if not isinstance(packet, ethernet):
        return

    src = packet.src
    dst = packet.dst

    ipp = packet.find('ipv4')
    if ipp and ipp.parsed:
        src_ip = str(ipp.srcip)
        dst_ip = str(ipp.dstip)
        
        if src_ip.startswith("10.0.0."):
            try:
                host_num = int(src_ip.split(".")[-1])
                if 1 <= host_num <= 4:
                    host_name = f"h{host_num}"
                    learn_host_mac(src, host_name)
            except:
                pass
        
        if dst_ip.startswith("10.0.0."):
            try:
                host_num = int(dst_ip.split(".")[-1])
                if 1 <= host_num <= 4:
                    host_name = f"h{host_num}"
                    learn_host_mac(dst, host_name)
            except:
                pass
    
    ipv6p = packet.find('ipv6')
    if ipv6p and ipv6p.parsed:
        src_ip6 = str(ipv6p.srcip)
        dst_ip6 = str(ipv6p.dstip)

        # h1-h4 en IPv6 → fd00::1 , fd00::2 , etc.
        for ip6 in [src_ip6, dst_ip6]:
            if ip6.startswith("fd00::"):
                try:
                    num = int(ip6.split("::")[1], 16)
                    if 1 <= num <= 4:
                        learn_host_mac(src if ip6 == src_ip6 else dst, f"h{num}")
                except:
                    pass
    
    arpp = packet.find('arp')
    if arpp and arpp.parsed:
        if arpp.opcode == arpp.REQUEST or arpp.opcode == arpp.REPLY:
            if arpp.protosrc:
                src_ip = str(arpp.protosrc)
                if src_ip.startswith("10.0.0."):
                    try:
                        host_num = int(src_ip.split(".")[-1])
                        if 1 <= host_num <= 4:
                            host_name = f"h{host_num}"
                            learn_host_mac(src, host_name)
                    except:
                        pass

    matched_rule = check_firewall_rules(packet, src, dst, dpid)
    if matched_rule:
        rule_type = matched_rule.get("type")
        ipv4p = packet.find('ipv4')
        ipv6p = packet.find('ipv6')
        udpp = packet.find('udp')
        tcpp = packet.find('tcp')

        # Regla port_block: instalar flow que bloquea el puerto específico
        if rule_type == "port_block":
            dst_port = matched_rule.get("dst_port")
            
            log.warning("FIREWALL: REGLA 1 ACTIVADA - puerto destino %s detectado (ipv4=%s, tcp=%s, udp=%s)", 
                       dst_port, ipv4p is not None, tcpp and tcpp.parsed, udpp and udpp.parsed)
            
            # Para IPv4, instalamos flows específicos por protocolo y puerto
            if ipv4p and ((tcpp and tcpp.parsed) or (udpp and udpp.parsed)):
                fm = of.ofp_flow_mod()
                fm.idle_timeout = 120
                fm.hard_timeout = 300
                fm.priority = 65535
                fm.match = of.ofp_match()
                fm.match.dl_type = 0x0800
                
                if tcpp and tcpp.parsed:
                    fm.match.nw_proto = 6
                    fm.match.tp_dst = tcpp.dstport
                    log.warning("FIREWALL: Instalando flow DROP para TCP puerto %s", tcpp.dstport)
                elif udpp and udpp.parsed:
                    fm.match.nw_proto = 17
                    fm.match.tp_dst = udpp.dstport
                    log.warning("FIREWALL: Instalando flow DROP para UDP puerto %s", udpp.dstport)
                
                try:
                    event.connection.send(fm)
                    log.warning("FIREWALL: ✓ Flow drop instalado en %s para regla id=%s (port_block: puerto %s)", 
                               switch_names.get(dpid, dpid), matched_rule.get("id"), dst_port)
                except Exception as e:
                    log.error("FIREWALL: ✗ Error instalando flow drop: %s", e)
            else:
                # Para IPv6 o casos sin L4, drop solo este paquete
                log.warning("FIREWALL: Paquete dropeado directamente - Regla %s (port_block: puerto %s)", 
                           matched_rule.get("id"), dst_port)
            return
        
        elif rule_type == "host_port_protocol_block":
            dst_port = matched_rule.get("dst_port")
            protocol = matched_rule.get("protocol", "").upper()
            
            # Para IPv4, instalamos flow específico con puerto y protocolo
            if ipv4p and ((protocol == "UDP" and udpp and udpp.parsed) or 
                         (protocol == "TCP" and tcpp and tcpp.parsed)):
                fm = of.ofp_flow_mod()
                fm.idle_timeout = 120
                fm.hard_timeout = 300
                fm.priority = 65535
                fm.buffer_id = event.ofp.buffer_id
                fm.match = of.ofp_match()
                fm.match.dl_type = 0x0800
                fm.match.dl_src = src
                
                if protocol == "UDP" and udpp and udpp.parsed:
                    fm.match.nw_proto = 17
                    fm.match.tp_dst = udpp.dstport
                elif protocol == "TCP" and tcpp and tcpp.parsed:
                    fm.match.nw_proto = 6
                    fm.match.tp_dst = tcpp.dstport
                
                try:
                    event.connection.send(fm)
                    log.warning("FIREWALL: Flow drop instalado en %s para regla id=%s (%s:%s %s)", 
                               switch_names.get(dpid, dpid), matched_rule.get("id"),
                               matched_rule.get("src_host"), dst_port, protocol)
                except Exception as e:
                    log.error("FIREWALL: Error instalando flow drop: %s", e)
            else:
                # Para IPv6 o casos donde no podemos parsear L4, solo drop del paquete
                log.warning("FIREWALL: Paquete dropeado - Regla %s (host_port_protocol): %s→%s %s", 
                           matched_rule.get("id"), matched_rule.get("src_host"), 
                           dst_port, protocol)
            return

        # Host pair block -> instalar flow que bloquea todo entre dos hosts
        elif rule_type == "host_pair_block":
            fm = of.ofp_flow_mod()
            fm.idle_timeout = 120
            fm.hard_timeout = 300
            fm.priority = 65535
            fm.buffer_id = event.ofp.buffer_id
            fm.match = of.ofp_match()
            fm.match.dl_src = src
            fm.match.dl_dst = dst
            
            if ipv4p:
                fm.match.dl_type = 0x0800
            elif ipv6p:
                fm.match.dl_type = 0x86dd
            
            try:
                event.connection.send(fm)
                log.warning("FIREWALL: Flow drop instalado en %s para regla id=%s (host_pair: %s↔%s)", 
                           switch_names.get(dpid, dpid), matched_rule.get("id"),
                           matched_rule.get("host1"), matched_rule.get("host2"))
            except Exception as e:
                log.error("FIREWALL: Error instalando flow drop: %s", e)
            return
        
        # Si no matcheó ningún tipo conocido, drop el paquete
        log.warning("FIREWALL: Paquete dropeado - Regla desconocida id=%s", matched_rule.get("id"))
        return
    
    mac_to_port[dpid][src] = in_port
    
    switch_name = switch_names.get(dpid, dpid)
    is_firewall = is_firewall_switch(dpid)
    log.debug("PacketIn at switch %s (firewall=%s): src=%s dst=%s in_port=%s", 
              switch_name, is_firewall, src, dst, in_port)

    if dst in mac_to_port[dpid]:
        out_port = mac_to_port[dpid][dst]
        fm = of.ofp_flow_mod()
        fm.priority = 100
        fm.match.dl_src = src
        fm.match.dl_dst = dst
        fm.match.in_port = in_port
        fm.actions.append(of.ofp_action_output(port=out_port))
        fm.idle_timeout = 30
        fm.hard_timeout = 60
        fm.data = event.ofp
        event.connection.send(fm)
        log.info("Instalado flow en switch %s: %s -> %s (puerto %s)", 
                switch_names.get(dpid, dpid), src, dst, out_port)
    else:
        msg = of.ofp_packet_out(data=event.ofp)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = in_port
        event.connection.send(msg)
        log.debug("Flooding packet on switch %s", switch_names.get(dpid, dpid))

def _handle_PortStatus(event):
    """
    Maneja los cambios de estado de los puertos de los switches.
    
    Args:
        event: Evento de cambio de estado de puerto
    """
    log.info("Port status change: %s", event)

def launch():
    """
    Inicializa el módulo l2_learning_custom.
    
    Carga la configuración del firewall y registra los listeners
    para los eventos de OpenFlow.
    """
    reset_switch_counter()
    load_firewall_config()
    
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.openflow.addListenerByName("PortStatus", _handle_PortStatus)
    log.info("l2_learning_custom cargado (con logging DEBUG en pox log.level)")

    # Registrar handler para SIGHUP: permite resetear el estado interno sin
    # reiniciar todo el proceso POX. Útil para ejecutar tests repetidos.
    def _handle_sighup(signum, frame):
        try:
            reset_state()
        except Exception as e:
            log.error("Error al resetear estado en SIGHUP: %s", e)

    try:
        signal.signal(signal.SIGHUP, _handle_sighup)
        log.info("l2_learning_custom: SIGHUP handler instalado - usa 'kill -HUP <pox_pid>' para resetear estado")
    except Exception:
        # En algunos entornos (p. ej. cuando POX se ejecuta en entornos especiales)
        # puede no ser posible instalar handlers de señal; no es crítico.
        log.debug("l2_learning_custom: No se pudo instalar handler SIGHUP")
