# pox/ext/l2_learning_custom.py
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
import pox.lib.packet as pkt
import json
import os

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
    
    Aplica las siguientes reglas:
    - Bloquear paquetes con puerto destino 80
    - Bloquear paquetes de h1 a puerto 5001 UDP
    - Bloquear comunicación entre dos hosts específicos
    
    Args:
        packet: Paquete parseado de POX
        src_mac: MAC de origen
        dst_mac: MAC de destino
        dpid: Identificador del switch
    
    Returns:
        True si el paquete debe ser bloqueado, False en caso contrario
    """
    if firewall_config is None:
        return False
    
    if not is_firewall_switch(dpid):
        return False
    
    log.info("FIREWALL: Verificando reglas en switch %s (dpid=%s)", switch_names.get(dpid, dpid), dpid)
    
    rules = firewall_config.get("rules", [])
    
    ipv4p = packet.find('ipv4')
    ipv6p = packet.find('ipv6')
    if not ipv4p and not ipv6p:
        log.debug("FIREWALL: Paquete no es IPv4 ni IPv6")
        return False

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
                    log.warning("FIREWALL: Paquete bloqueado - Regla %d: puerto destino %d (TCP)", 
                               rule.get("id"), dst_port)
                    return True
                if udpp and udpp.parsed and udpp.dstport == dst_port:
                    log.warning("FIREWALL: Paquete bloqueado - Regla %d: puerto destino %d (UDP)", 
                               rule.get("id"), dst_port)
                    return True
        
        if rule_type == "host_port_protocol_block":
            src_host = rule.get("src_host")
            dst_port = rule.get("dst_port")
            protocol = rule.get("protocol", "").upper()
            
            if src_host and dst_port:
                src_host_actual = get_host_from_mac(src_mac)
                log.debug("FIREWALL: Regla 2 - src_host_actual=%s, src_host=%s, protocol=%s, dst_port=%d", 
                         src_host_actual, src_host, protocol, dst_port)
                
                if src_host_actual == src_host:
                    log.info("FIREWALL: Regla 2 - Host coincide! src_host_actual=%s == src_host=%s", 
                            src_host_actual, src_host)
                    if protocol == "UDP":
                        udpp = packet.find('udp')
                        log.info("FIREWALL: Regla 2 UDP - udpp=%s, parsed=%s, dstport=%s, esperado=%d", 
                                udpp is not None, udpp.parsed if udpp else False, 
                                udpp.dstport if udpp and udpp.parsed else None, dst_port)
                        if udpp and udpp.parsed and udpp.dstport == dst_port:
                            log.warning("FIREWALL: Paquete bloqueado - Regla %d: %s -> puerto %d (UDP)", 
                                       rule.get("id"), src_host, dst_port)
                            return True
                        else:
                            log.info("FIREWALL: Regla 2 UDP - No coincide: dstport=%s != %d o no parseado", 
                                    udpp.dstport if udpp and udpp.parsed else None, dst_port)
                    elif protocol == "TCP":
                        tcpp = packet.find('tcp')
                        log.debug("FIREWALL: Regla 2 TCP - tcpp=%s, parsed=%s, dstport=%s", 
                                 tcpp, tcpp.parsed if tcpp else None, tcpp.dstport if tcpp and tcpp.parsed else None)
                        if tcpp and tcpp.parsed and tcpp.dstport == dst_port:
                            log.warning("FIREWALL: Paquete bloqueado - Regla %d: %s -> puerto %d (TCP)", 
                                       rule.get("id"), src_host, dst_port)
                            return True
        
        if rule_type == "host_pair_block":
            host1 = rule.get("host1")
            host2 = rule.get("host2")
            
            if host1 and host2:
                src_host = get_host_from_mac(src_mac)
                dst_host = get_host_from_mac(dst_mac)
                
                log.debug("FIREWALL: Verificando regla 3 - src_host=%s, dst_host=%s, host1=%s, host2=%s", 
                         src_host, dst_host, host1, host2)
                
                if (src_host == host1 and dst_host == host2) or \
                   (src_host == host2 and dst_host == host1):
                    log.warning("FIREWALL: Paquete bloqueado - Regla %d: comunicación entre %s y %s", 
                               rule.get("id"), host1, host2)
                    return True
    
    return False

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

    if check_firewall_rules(packet, src, dst, dpid):
        # Instalar flow de bloqueo en el switch (siguiendo ejemplo de l2_learning.py)
        fm = of.ofp_flow_mod()
        
        # Crear match usando from_packet SIN in_port (para coincidir en cualquier puerto)
        fm.match = of.ofp_match.from_packet(packet)
        
        # Quitar tp_src del match para que coincida con cualquier puerto fuente
        # Solo nos importa el puerto destino
        fm.match.tp_src = 0  # 0 significa wildcard en OpenFlow 1.0
        
        # Incluir buffer_id para descartar el paquete actual también
        fm.buffer_id = event.ofp.buffer_id
        
        # Timeouts
        fm.idle_timeout = 120
        fm.hard_timeout = 300
        
        # Prioridad alta para que prevalezca sobre flows de forwarding
        fm.priority = 65535
        
        # NO agregamos acciones = drop
        # Enviar al switch
        event.connection.send(fm)
        
        # Log para debugging
        tcpp = packet.find('tcp')
        udpp = packet.find('udp')
        if udpp and udpp.parsed:
            proto_str = "UDP"
            port_str = str(udpp.dstport)
        elif tcpp and tcpp.parsed:
            proto_str = "TCP"
            port_str = str(tcpp.dstport)
        else:
            proto_str = "ICMP/Other"
            port_str = "N/A"
        
        log.warning("FIREWALL: Flow drop instalado en %s - proto=%s port=%s", 
                   switch_names.get(dpid, dpid), proto_str, port_str)
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
