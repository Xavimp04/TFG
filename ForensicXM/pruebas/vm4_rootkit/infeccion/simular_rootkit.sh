#!/bin/bash
# =============================================================
# Escenario VM4 - ALTERNATIVA SIN RIESGO al rootkit LKM real
# Módulo de ForensicXM probado: -k (rootkit)
#
# Si NO quieres cargar un módulo de kernel real, este script
# simula la MISMA discrepancia que detecta tu cross-view
# validation: crea una entrada en /sys/module/ que NO existe
# en /proc/modules.
#
# Tu analizar_rootkits.c recorre /sys/module/, comprueba que
# cada módulo tenga el fichero 'initstate' (para distinguir
# LKM de built-in) y verifica si aparece en /proc/modules.
# Aquí creamos justo eso: un directorio con 'initstate' que
# /proc/modules nunca reportará.
#
# LIMITACIÓN METODOLÓGICA (mencionar en el informe): esto valida
# la LÓGICA DE COMPARACIÓN de la herramienta, pero no un rootkit
# real en kernel. Para validación completa usar ocultador.c.
#
# Ejecutar como root en la VM. Es reversible (ver --limpiar).
# =============================================================
set -e
if [ "$EUID" -ne 0 ]; then echo "Ejecuta con sudo"; exit 1; fi

FAKE=/sys/module/rootkit_sim

if [ "$1" == "--limpiar" ]; then
  # /sys es un sysfs y normalmente no permite rmdir de entradas
  # creadas a mano; si tu kernel lo permite se borra, si no,
  # basta con reiniciar la VM.
  rmdir $FAKE 2>/dev/null && echo "[+] Simulación eliminada" \
    || echo "[!] No se pudo borrar (reinicia la VM para limpiar)"
  exit 0
fi

echo "[*] Simulando módulo oculto (VM4, modo sin riesgo)..."

# Intento 1: crear el directorio directamente en sysfs
if mkdir -p $FAKE 2>/dev/null; then
  echo "live" > $FAKE/initstate 2>/dev/null || true
  echo "[+] Creado $FAKE con initstate"
else
  echo "[!] El kernel no permite crear entradas en /sys/module."
  echo "    Usa la opción del módulo real (ocultador.c) en su lugar."
  exit 1
fi

echo ""
echo "[+] Verifica la discrepancia:"
echo "      ls /sys/module/rootkit_sim   -> existe"
echo "      grep rootkit_sim /proc/modules -> NO aparece"
echo "[+] Analiza:  sudo ./bin/forensicXM -k"
echo "[+] Limpiar:  sudo ./simular_rootkit.sh --limpiar"
