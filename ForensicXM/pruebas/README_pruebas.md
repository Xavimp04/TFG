# Banco de pruebas de ForensicXM — Guía de uso

Conjunto de escenarios controlados para validar la herramienta ForensicXM
contra amenazas simuladas. Pensado para el capítulo de validación/resultados
del TFG.

Configuración objetivo: **VirtualBox**, base **Ubuntu 24.04** + una VM
**Fedora** para validación multi-distribución. **8 VMs** en total: 6 en
modo *live* y 2 en modo *dead-box*.

## Advertencia

Todo el código de esta carpeta es **deliberadamente "malicioso" en apariencia**
pero inofensivo en efecto (no exfiltra datos, no se propaga, no daña el sistema).
Aun así, **ejecútalo SOLO en máquinas virtuales desechables y con snapshot
previo**. Nunca en tu equipo de trabajo.

## Metodología recomendada

1. Instala una VM base Ubuntu 24.04 en VirtualBox. Instala otra Fedora aparte.
2. Clona la base Ubuntu para VM0..VM4 (clon completo desde VM0 limpia).
3. En cada VM: **snapshot limpio** -> copiar ForensicXM compilado ->
   copiar los scripts del escenario correspondiente.
4. Ejecuta el script de infección del escenario.
5. Ejecuta ForensicXM (modo módulo y modo `-r` reporte completo).
6. Guarda los reportes `.txt` y la salida de consola.
7. Restaura el snapshot para dejar la VM limpia.

La **VM0 de control** se analiza sin infectar: sirve para medir falsos
positivos y demostrar que la herramienta no "ve cosas donde no las hay".

Las **VM6 y VM7** se crean clonando VM4 y VM1 respectivamente, y se
analizan en modo dead-box (ver sección específica más abajo).

### Nota sobre VirtualBox

Para que los binarios de red (`fake_backdoor`) y el análisis tengan sentido,
basta con la red NAT por defecto. Si quieres que las IPs de los scripts
(`192.168.56.x`) sean coherentes, configura una red "solo-anfitrión"
(host-only) — pero no es imprescindible: las IPs solo aparecen como texto
en logs y cron, no se conecta a ellas de verdad.

## Tabla de cobertura: amenaza → módulo

| VM  | Distro | Modo     | Escenario                  | Amenaza simulada                            | Módulo(s) | Indicador que debe detectar |
|-----|--------|----------|----------------------------|---------------------------------------------|-----------|------------------------------|
| VM0 | Ubuntu | live     | Control limpio             | (ninguna)                                   | todos     | Idealmente 0 alertas críticas |
| VM1 | Ubuntu | live     | Usuarios + persistencia    | UID 0 oculto (`sysadmin`)                   | `-u`      | Segundo usuario con UID 0 |
| VM1 | Ubuntu | live     |                            | Cuenta sin contraseña (`webupdate`)         | `-u`      | Campo password vacío en shadow |
| VM1 | Ubuntu | live     |                            | Hash MD5 débil                              | `-u`      | Hash `$1$` marcado DÉBIL |
| VM1 | Ubuntu | live     |                            | Cron malicioso (`* * * * *` + curl)         | `-p`      | curl/wget en cron.d |
| VM1 | Ubuntu | live     |                            | Servicio systemd malicioso                  | `-p`      | python en ExecStart, Restart=always |
| VM1 | Ubuntu | live     | Timestomping (extra)       | Nanosegundos a cero                         | `-i`      | tv_nsec = 0 en M y A |
| VM1 | Ubuntu | live     |                            | Modificación anterior a creación (M < B)    | `-i`      | mtime < btime |
| VM2 | Ubuntu | live     | Red + memoria              | Listener en puerto 4444                     | `-n`      | Puerto en LISTEN + mapeo PID |
| VM2 | Ubuntu | live     |                            | Proceso con región RWX                      | `-m`      | Región rwx en /proc/pid/maps |
| VM2 | Ubuntu | live     |                            | Binario borrado en ejecución                | `-m`      | exe -> "(deleted)" |
| VM3 | Ubuntu | live     | Capabilities + logs        | `cap_sys_ptrace` + `cap_net_raw` en no-root | `-c`      | Proceso no-root con caps críticas |
| VM3 | Ubuntu | live     |                            | Fuerza bruta SSH (35 intentos)              | `-l`      | "Failed password" repetido |
| VM4 | Ubuntu | live     | Rootkit LKM                | Módulo oculto de /proc/modules              | `-k`      | Discrepancia sysfs vs procfs |
| VM5 | Fedora | live     | Multi-distro               | UID 0 oculto (`rhsupport`)                  | `-u`      | Segundo usuario con UID 0 en RHEL |
| VM5 | Fedora | live     |                            | Cuenta sin contraseña (`patchsvc`)          | `-u`      | Campo password vacío |
| VM5 | Fedora | live     |                            | Cron + systemd maliciosos                   | `-p`      | curl en cron.d, python en service |
| VM5 | Fedora | live     |                            | Fuerza bruta en `/var/log/secure`           | `-l`      | **Fallback de log RHEL funciona** |
| VM6 | Ubuntu | dead-box | Limitaciones (clon VM4)    | Rootkit cargado en kernel (volátil)         | `-k`      | **No detectable** (módulo omitido) |
| VM7 | Ubuntu | dead-box | Capacidades (clon VM1)     | Backdoors + persistencia (estáticos)        | `-u -p -l`| Detección idéntica al modo live |

## Orden de archivos por VM

### VM0 — control (Ubuntu)
- `verificar_control.sh` — ejecuta ForensicXM completo sobre la VM limpia.

### VM1 — usuarios + persistencia + timestomping (Ubuntu)
- `infectar_vm1.sh` — usuarios maliciosos y persistencia. Ejecutar con sudo.
- `infectar_vm1_timestomp.sh` — ficheros con fechas manipuladas. Ejecutar como
  usuario normal. Cubre el módulo `-i`.

### VM2 — red + memoria (Ubuntu)
- `fake_backdoor.c` — listener en puerto 4444.
- `rwx_proc.c` — proceso con memoria RWX.
- `lanzar_vm2.sh` — compila los anteriores + `self_delete.c` y los lanza.

### VM3 — capabilities + logs (Ubuntu)
- `cap_holder.c` — binario inocuo que recibe las capabilities.
- `infectar_vm3.sh` — aplica `setcap` e inyecta los eventos de fuerza bruta.
  Tras ejecutarlo, lanzar `./cap_holder &` como **usuario normal**.

### VM4 — rootkit LKM real (Ubuntu)
- `ocultador.c` + `Makefile` — módulo de kernel real que se oculta.
  Requiere: `sudo apt install build-essential linux-headers-$(uname -r)`.
  Compilar: `make`. Cargar: `sudo insmod ocultador.ko`.
  Una vez cargado NO se puede descargar (está fuera de la lista): para limpiar,
  restaurar snapshot o reiniciar.

### VM5 — Fedora (validación multi-distro)
- `infectar_vm5_fedora.sh` — usuarios, persistencia y fuerza bruta en
  `/var/log/secure`. Ejecutar con sudo en la VM Fedora.

### VM6 — dead-box limitaciones (clon de VM4)
- `reporte_deadbox_vm6.txt` — reporte generado sobre la imagen montada.
- `vm6_evidencia.sha256` — firma de la imagen RAW (cadena de custodia).
- Procedimiento de adquisición: ver sección siguiente.

### VM7 — dead-box capacidades (clon de VM1)
- `reporte_deadbox_vm7.txt` — reporte generado sobre la imagen montada.
- `vm7_evidencia.sha256` — firma de la imagen RAW (cadena de custodia).
- Procedimiento de adquisición: ver sección siguiente.

## Procedimiento de adquisición dead-box (VM6 y VM7)

El procedimiento es idéntico para ambas máquinas y reproduce la cadena
de custodia que exige el RFC 3227.

### 1. Clonación y conversión a formato RAW

Desde el sistema anfitrión, con la VM **apagada**:

```bash
VBoxManage clonemedium disk \
  "/home/xavimp/VirtualBox VMs/VM7/VM7-disk1.vdi" \
  ~/Desktop/evidencia_deadbox/vm7_evidencia.raw \
  --format RAW
```

### 2. Sellado criptográfico (cadena de custodia)

```bash
sha256sum vm7_evidencia.raw | tee vm7_evidencia.sha256
# VM6: 08b367d3f4769a3120f5773245bc0110afebd2aba57b0345f93fce0ca125ecd0
# VM7: e898f82c7f83b98bf083cc9b6c1ab86b3ae51a22116527e3ae3e56d94b08a70d
```

### 3. Mapeo del dispositivo y particiones

```bash
sudo losetup --find --partscan --show vm7_evidencia.raw
# Devuelve /dev/loopN (ej. /dev/loop24)
sudo partprobe /dev/loop24
```

### 4. Activación de LVM

Ubuntu usa LVM, la partición raíz no es directamente montable:

```bash
sudo apt install lvm2    # si no está instalado
sudo vgscan
sudo vgchange -ay
sudo lvs
# Muestra: ubuntu-lv  ubuntu-vg  -wi-a-----  <11,50g
```

### 5. Montaje en solo-lectura

```bash
sudo mkdir -p /mnt/vm7_evidencia
sudo mount -o ro /dev/ubuntu-vg/ubuntu-lv /mnt/vm7_evidencia
```

### 6. Ejecución de ForensicXM en modo dead-box

```bash
sudo ./bin/forensicXM -d /mnt/vm7_evidencia -r reporte_deadbox_vm7.txt
```

### 7. Limpieza entre imágenes

Antes de montar una segunda imagen, desmontar la anterior para evitar
conflictos de nombres de volume group:

```bash
sudo umount /mnt/vm7_evidencia
sudo vgchange -an ubuntu-vg
sudo losetup -d /dev/loop24
```

### Nota sobre conflictos de LVM

Todas las VMs de Ubuntu se clonaron de la misma VM0, así que comparten
el nombre del volume group (`ubuntu-vg`). Si se montan dos imágenes a
la vez, LVM detecta un UUID duplicado. La solución es desmontar
completamente una imagen antes de activar la siguiente (paso 7).

## Qué guardar para el informe

Para cada VM, conserva:
- La salida de consola de cada módulo individual.
- El reporte completo `reporte_vmN.txt` generado con `-r`.
- (Opcional) La salida JSON con `-j` para VM4.
- Captura del estado "antes" (ej. `lsmod`, `getcap`, `cat /etc/passwd`,
  `ls -la --time-style=full-iso` para timestomping).
- Para VM4: captura de `lsmod | grep ocultador` (vacío) y
  `ls /sys/module/ocultador` (existe) — la prueba visual de la discrepancia.
- Para VM5: captura de que el log analizado es `/var/log/secure`.
- Para VM6/VM7: el fichero `.sha256` con la firma de la imagen y los
  reportes dead-box generados.
