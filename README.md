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
