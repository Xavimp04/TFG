#!/bin/bash
# =============================================================
# Escenario VM2 - Red + Memoria (orquestador)
# Módulos de ForensicXM probados: -n (red), -m (memoria)
# Ejecutar DENTRO de la VM de pruebas. Snapshot previo.
#
# Lanza tres "procesos maliciosos" simultáneos:
#   1. fake_backdoor  -> puerto 4444 en LISTEN        (módulo -n)
#   2. rwx_proc       -> región de memoria RWX        (módulo -m)
#   3. malware_test   -> binario borrado en ejecución (módulo -m)
#
# El nº 3 reutiliza tests/self_delete.c de tu propio repo.
# IMPORTANTE: self_delete.c hace unlink("tests/malware_test"),
# así que hay que compilarlo con ESE nombre y ruta exactos.
# =============================================================
set -e

echo "[*] Preparando escenario VM2..."

# --- Compilar los binarios ---
gcc fake_backdoor.c -o fake_backdoor
gcc rwx_proc.c -o rwx_proc

# El binario que se autoborra: ruta esperada por self_delete.c
mkdir -p tests
# Ajusta esta ruta a donde tengas el self_delete.c de tu repo:
SELF_DELETE_SRC="../../ForensicXM/tests/self_delete.c"
if [ -f "$SELF_DELETE_SRC" ]; then
  gcc "$SELF_DELETE_SRC" -o tests/malware_test
else
  echo "[!] No encuentro self_delete.c en $SELF_DELETE_SRC"
  echo "    Cópialo aquí o ajusta la variable SELF_DELETE_SRC."
  exit 1
fi

# --- Lanzar los tres procesos en segundo plano ---
./fake_backdoor &
PID_BD=$!
./rwx_proc &
PID_RWX=$!
./tests/malware_test &
PID_DEL=$!

sleep 2  # damos tiempo a self_delete a borrarse

echo ""
echo "[+] Procesos lanzados:"
echo "    fake_backdoor  PID $PID_BD  (puerto 4444 LISTEN)"
echo "    rwx_proc       PID $PID_RWX (memoria RWX)"
echo "    malware_test   PID $PID_DEL (binario borrado)"
echo ""
echo "[+] Ahora analiza con:"
echo "      sudo ./bin/forensicXM -n -m"
echo "      sudo ./bin/forensicXM -r reporte_vm2.txt"
echo ""
echo "[+] Para terminar los procesos al acabar:"
echo "      kill $PID_BD $PID_RWX $PID_DEL"
