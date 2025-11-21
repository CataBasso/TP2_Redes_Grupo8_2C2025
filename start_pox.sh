#!/bin/bash
# Script para iniciar POX con logging a archivo

cd "$(dirname "$0")/pox" || exit 1
export PYTHONPATH=$PYTHONPATH:$(pwd)/../pox_ext

# Crear archivo de log con timestamp
LOG_FILE="../pox_$(date +%Y%m%d_%H%M%S).log"

echo "Iniciando POX..."
echo "Logs se guardarán en: $LOG_FILE"
echo "Presiona Ctrl+C para detener"

./pox.py log.level --DEBUG l2_learning_custom 2>&1 | tee "$LOG_FILE"
#python3 ./pox.py log.level --DEBUG l2_learning_custom 2>&1 | tee "$LOG_FILE" 
