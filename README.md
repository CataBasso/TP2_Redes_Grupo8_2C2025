# TP2_Redes_Grupo8_2C2025

## Instalaciones:

### 1. Clonarse POX

```bash
git clone https://github.com/noxrepo/pox.git
```

### 2. Agregar la ruta del L2-learning a POX

```bash
cd pox
cd ext
export PYTHONPATH=$PYTHONPATH:/mnt/d/fiuba/redes/TP2_Redes_Grupo8_2C2025/pox_ext
cd ..
```
## Probar correcto funcionamiento de la topologia:

### 1. Levantar POX:

```bash
# Desde /pox
./pox.py log.level --DEBUG l2_learning_custom
```

### 2. Ejecutar topologia con Mininet

```bash
# Siendo n la cantidad de switches que queres tener
sudo python3 topologia.py n
```

### 3. Verificacion 

```bash
# Desde la CLI de Mininet
mininet> pingall
```

## Probar el Firewall:

El firewall está configurado en el switch `s2` (configurable en `firewall_rules.json`). Las reglas son:

1. **Regla 1**: Bloquear todos los paquetes con puerto destino 80 (HTTP)
2. **Regla 2**: Bloquear paquetes de h1 a puerto 5001 UDP
3. **Regla 3**: Bloquear comunicación entre h1 y h3

### Pasos para probar:

#### 1. Levantar POX (en una terminal):
```bash
cd pox
export PYTHONPATH=$PYTHONPATH:$(pwd)/../pox_ext
./pox.py log.level --DEBUG l2_learning_custom 2>&1 | tee ../pox.log
```

O para guardar solo en archivo (sin mostrar en pantalla):
```bash
cd pox
export PYTHONPATH=$PYTHONPATH:$(pwd)/../pox_ext
./pox.py log.level --DEBUG l2_learning_custom > ../pox.log 2>&1 &
```

Los logs se guardarán en `pox.log` en el directorio raíz del proyecto.

#### 2. Levantar Mininet (en otra terminal):
```bash
sudo python3 topologia.py 4
```

#### 3. Verificar que el firewall está activo:
En los logs de POX deberías ver:
```
*** Este switch (s2) es el FIREWALL ***
```

### Pruebas de las reglas:

#### Prueba Regla 1: Bloqueo de puerto 80 (HTTP)

**En Mininet CLI:**
```bash
# Terminal 1: Iniciar servidor HTTP en h2
mininet> h2 python3 -m http.server 80 &

# Terminal 2: Intentar conectar desde h1 (debe fallar)
mininet> h1 curl http://10.0.0.2:80
```

**Resultado esperado**: La conexión debe fallar. En los logs de POX verás:
```
FIREWALL: Paquete bloqueado - Regla 1: puerto destino 80 (TCP)
```

**Verificar que otros puertos funcionan:**
```bash
# Servidor en puerto 8080 (no bloqueado)
mininet> h2 python3 -m http.server 8080 &
mininet> h1 curl http://10.0.0.2:8080
```
**Resultado esperado**: Debe funcionar correctamente.

#### Prueba Regla 2: Bloqueo h1 -> puerto 5001 UDP

**En Mininet CLI:**
```bash
# Terminal 1: Iniciar servidor iperf UDP en h2 puerto 5001
mininet> h2 iperf -s -u -p 5001 &

# Terminal 2: Intentar conectar desde h1 (debe fallar)
mininet> h1 iperf -c 10.0.0.2 -u -p 5001 -t 5
```

**Resultado esperado**: No debe haber transferencia. En los logs de POX:
```
FIREWALL: Paquete bloqueado - Regla 2: h1 -> puerto 5001 (UDP)
```

**Verificar que desde otros hosts funciona:**
```bash
# Desde h2 (no bloqueado)
mininet> h2 iperf -c 10.0.0.3 -u -p 5001 -t 5
```
**Resultado esperado**: Debe funcionar si h3 está escuchando.

#### Prueba Regla 3: Bloqueo comunicación h1 <-> h3

**En Mininet CLI:**
```bash
# Intentar ping desde h1 a h3 (debe fallar)
mininet> h1 ping -c 3 10.0.0.3
```

**Resultado esperado**: 100% packet loss. En los logs de POX:
```
FIREWALL: Paquete bloqueado - Regla 3: comunicación entre h1 y h3
```

**Verificar que h1 puede comunicarse con otros hosts:**
```bash
# h1 -> h2 (debe funcionar)
mininet> h1 ping -c 3 10.0.0.2

# h1 -> h4 (debe funcionar)
mininet> h1 ping -c 3 10.0.0.4
```

**Verificar que h3 puede comunicarse con otros hosts:**
```bash
# h3 -> h2 (debe funcionar)
mininet> h3 ping -c 3 10.0.0.2

# h3 -> h4 (debe funcionar)
mininet> h3 ping -c 3 10.0.0.4
```

### Notas importantes:

- **El firewall solo se aplica en el switch configurado** (`s2` por defecto)
- Si el firewall está en un switch que no está en el camino entre dos hosts, las reglas no se aplicarán
- Los logs de POX muestran cada paquete bloqueado con la regla aplicada
- Para ver más detalles, usar `log.level --DEBUG` en POX

### Verificar con iperf (como se pide en el PDF):

**Prueba completa con iperf TCP:**
```bash
# Servidor en h2
mininet> h2 iperf -s -p 5000 &

# Cliente desde h1
mininet> h1 iperf -c 10.0.0.2 -p 5000 -t 10
```

**Prueba con iperf UDP:**
```bash
# Servidor en h2
mininet> h2 iperf -s -u -p 5001 &

# Cliente desde h1 (debe ser bloqueado por Regla 2)
mininet> h1 iperf -c 10.0.0.2 -u -p 5001 -t 10

# Cliente desde h2 (debe funcionar)
mininet> h2 iperf -c 10.0.0.3 -u -p 5001 -t 10
```
