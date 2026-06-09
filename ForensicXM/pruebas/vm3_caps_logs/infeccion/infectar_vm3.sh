#!/bin/bash
# =============================================================
# Escenario VM3 - Capabilities robadas + Fuerza bruta en logs
# Módulos de ForensicXM probados: -c (capabilities), -l (logs)
# Ejecutar como root DENTRO de la VM de pruebas.
# Hacer snapshot ANTES.
# =============================================================
set -e
if [ "$EUID" -ne 0 ]; then echo "Ejecuta con sudo"; exit 1; fi

echo "[*] Infectando VM3 (capabilities + logs)..."

# --- 1. Compilar y dotar de capabilities al binario inocuo ---
if [ ! -f cap_holder ]; then
  gcc cap_holder.c -o cap_holder
fi
# Le robamos dos capabilities críticas SIN que el binario sea root
setcap cap_sys_ptrace,cap_net_raw+ep ./cap_holder
echo "[+] Capabilities aplicadas a ./cap_holder:"
getcap ./cap_holder

# --- 2. Inyectar eventos de fuerza bruta SSH en auth.log ---
# Tu analizar_logs() busca "Failed password" y "authentication failure".
AUTHLOG=/var/log/auth.log
TS=$(date "+%b %e %H:%M:%S")
HOST=$(hostname)
for i in $(seq 1 25); do
  echo "$TS $HOST sshd[$((1000+i))]: Failed password for invalid user admin from 192.168.56.66 port $((40000+i)) ssh2" >> $AUTHLOG
done
for i in $(seq 1 10); do
  echo "$TS $HOST sshd[$((2000+i))]: Failed password for root from 10.0.0.5 port $((50000+i)) ssh2" >> $AUTHLOG
done
echo "[+] 35 eventos de fuerza bruta inyectados en $AUTHLOG"

echo ""
echo "[+] AHORA, como usuario NORMAL (no root), ejecuta:  ./cap_holder &"
echo "[+] Y luego analiza:  sudo ./bin/forensicXM -c -l"
