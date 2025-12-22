# Apéndice: Referencia Técnica de Arquitectura y Forense en Linux

Este apéndice recopila las estructuras de directorios, tablas de referencia de permisos, ubicaciones de registros (logs) y comandos esenciales para el análisis forense en sistemas GNU/Linux, WSL y entornos virtualizados.

## A. Estructura del Sistema de Archivos (FHS) y Artefactos Forenses

El estándar de jerarquía del sistema de archivos (FHS) define la ubicación de los archivos. Desde una perspectiva forense, cada directorio contiene artefactos específicos de valor investigativo.

| Directorio | Contenido y Función Principal | Implicaciones Forenses |
|-----------|-------------------------------|-------------------------|
| `/` (Raíz) | Base del sistema de archivos. | Punto de inicio para la adquisición de la imagen forense. |
| `/bin` & `/sbin` | Binarios esenciales (`cp`, `rm`, `ls`). `/sbin` contiene binarios de administración (requieren root). | Contienen utilidades que podrían ser usadas para actividad maliciosa o gestión del sistema. |
| `/boot` | Archivos de arranque (Kernel, initramfs). | Esencial para analizar la configuración de arranque y versiones del kernel. |
| `/dev` | Archivos de dispositivos hardware (discos, terminales). | Los dispositivos de almacenamiento (`/dev/sda`) se analizan a través de estos archivos. |
| `/etc` | Configuración del sistema y programas (usuarios, red, DNS). | Ubicación crítica: hashes de contraseñas, configuración de servicios y red. |
| `/home` | Directorios personales de usuarios (excepto root). | Almacena datos personales, historial de shell (`.bash_history`) y configuraciones de usuario. |
| `/lib` | Librerías de código compartido (archivos `.so`). | Permiten identificar librerías utilizadas por programas maliciosos. |
| `/proc` | Sistema de archivos virtual con información de procesos y kernel en ejecución. | Crítico para *Live Response*: estado del sistema y procesos activos en RAM. |
| `/root` | Directorio personal del superusuario. | Contenido de alta sensibilidad forense, accesible solo con privilegios elevados. |
| `/tmp` | Archivos temporales, escribible por todos. | Lugar común para scripts y malware; su contenido suele perderse al reiniciar. |
| `/var` | Datos variables (logs, caché, spool). | Ruta importante para evidencia estática, especialmente `/var/log`. |

# B. Gestión de Identidad y Permisos

## 1. Referencia de Permisos y Modos Especiales

La seguridad en Linux se basa en permisos de lectura (4), escritura (2) y ejecución (1). Además, existen permisos especiales críticos para la escalada de privilegios.

| Tipo de Permiso | Valor Octal | Representación Simbólica | Descripción y Riesgo Forense |
|-----------------|-------------|---------------------------|-------------------------------|
| Set UID | 4000 | `rws` (en usuario) | Ejecuta el binario con privilegios del propietario (riesgoso si es root). |
| Set GID | 2000 | `rws` (en grupo) | Archivos creados en directorio heredan el grupo. Ejecutables corren con permisos del grupo. |
| Sticky Bit | 1000 | `t` (al final) | Solo el dueño o root pueden borrar archivos en un directorio compartido (ej. `/tmp`). |

Un comando `chmod 777` en el historial indica un intento de saltarse controles de acceso.

## 2. Algoritmos de Hashing de Contraseñas

En el archivo `/etc/shadow`, el prefijo del hash identifica el algoritmo criptográfico utilizado.

| Algoritmo | Prefijo | Nivel de Seguridad |
|-----------|---------|--------------------|
| Yescrypt | `$y$` | Alto (estándar moderno, resistente a cracking offline). |
| SHA-512 | `$6$` | Alto. |
| Blowfish | `$2`, `$2a`, `$2y$` | Medio. |
| MD5 | `$1$` | Bajo (obsoleto). |

# C. Guía de Logs y Auditoría del Sistema

La adquisición forense debe capturar todo el contenido de `/var/log`. A continuación se detallan las ubicaciones y herramientas de análisis.

## 1. Logs de Autenticación y Sistema (Texto Plano)

| Tipo de Log | Debian/Ubuntu | RHEL/Fedora/CentOS | Contenido Clave |
|-------------|---------------|---------------------|------------------|
| General | `/var/log/syslog` | `/var/log/messages` | Resumen global, kernel, servicios. |
| Autenticación | `/var/log/auth.log` | `/var/log/secure` | Logins (SSH, su, sudo), fallos y éxitos. |
| Kernel | `/var/log/kern.log` | Systemd Journal | Eventos de bajo nivel del núcleo. |

## 2. Logs Binarios (Requieren Herramientas Específicas)

Estos archivos no pueden leerse directamente; requieren comandos específicos.

| Archivo | Ubicación Típica | Comando de Lectura | Descripción |
|---------|------------------|---------------------|-------------|
| `btmp` | `/var/log/btmp` | `lastb` | Intentos de inicio de sesión fallidos. |
| `wtmp` | `/var/log/wtmp` | `last` | Histórico de logins, reinicios y apagados. |
| `utmp` | `/run/utmp` | `who`, `w` | Usuarios conectados actualmente. |
| `lastlog` | `/var/log/lastlog` | `lastlog` | Último login registrado por cada usuario. |

**Técnica forense (Dead Box):** si no se pueden ejecutar los comandos, usar `strings` o montar el sistema para usar `last -f`.

## 3. Logs de Aplicaciones Críticas

- **Apache/Nginx:** `/var/log/apache2` o `/var/log/nginx`. Buscar patrones de web shells, inyecciones SQL, user agents sospechosos.  
- **Auditd:** `/var/log/audit/audit.log`. Registro detallado, resistente a manipulación.  
- **Sysmon for Linux:** Registra en syslog/messages en formato XML. Requiere `sysmon_log_view`.

# D. Forense en Entornos Virtualizados y Contenedores

## 1. Windows Subsystem for Linux (WSL 2)

- **Ubicación del disco:**  
  `C:\Users\[Usuario]\AppData\Local\Packages\[Paquete_Distro]\LocalState\ext4.vhdx`  
- **Formato:** VHDX con sistema de archivos ext4.  
- **Artefactos:** Igual que en Linux: `.bash_history`, `/etc/shadow`, etc.

## 2. Contenedores (Docker)

Metodología en incidentes:

- **Aislamiento:** `docker stop` o `docker pause`.  
- **Adquisición:**  
  - Metadatos: `docker inspect`  
  - Logs: `docker logs`  
  - Sistema de archivos: en `/var/lib/docker` del host  
- **Análisis:** Revisar capas del contenedor en busca de archivos modificados o maliciosos.


## 3. VMware ESXi (Logs y Adquisición)

### Logs Principales

Ubicados en `/var/log` del hipervisor:

- **VMkernel.log**  
  Eventos del kernel virtual, errores de hardware virtual y fallos de I/O.

- **Shell.log**  
  Auditoría de comandos ejecutados en el hipervisor.

- **Auth.log**  
  Eventos de autenticación y acceso administrativo.

### Adquisición Forense

#### Memoria RAM

- **Requisito:**  
  Snapshot de la máquina virtual **incluyendo memoria**.

- **Archivos a extraer:**
  - `.vmem` → Contenido completo de la RAM
  - `.vmsn` → Metadatos y offsets de memoria

- **Nota Forense:**  
  Ambos archivos son necesarios para un análisis coherente de memoria.

#### Disco

- **Estado de la VM:**  
  Máquina **apagada**.

- **Archivo relevante:**
  - `-flat.vmdk` → Contiene los datos reales del disco

- **Importante:**  
  El archivo `.vmdk` pequeño es solo un **descriptor**, no contiene datos útiles.

## 4. Microsoft Hyper-V

### Adquisición de Memoria

- **Método:**  
  Crear **Checkpoint en modo Estándar** (no Production).

- **Archivo forense:**
  - `.vmrs` → Contenido de la memoria RAM de la VM

### Adquisición de Disco

- **Método recomendado:**  
  Exportación de la máquina virtual.

- **Formato resultante:**
  - `.vhdx`


# E. Análisis Forense de Sistemas de Archivos (EXT, XFS, BTRFS)

El análisis de la capa del sistema de archivos permite recuperar datos eliminados y establecer cronologías precisas.

## 1. Cronología Forense: Marcas de Tiempo (Timestamps)

La interpretación correcta de los tiempos es vital para reconstruir eventos.

| Marca | Nombre | Significado | Nota Importante |
|------|-------|------------|----------------|
| M time | Modification | Modificación del contenido del archivo | Se altera al editar el archivo |
| A time | Access | Último acceso o lectura | En Linux moderno (`relatime`), no se actualiza siempre para ahorrar rendimiento |
| C time | Change | Cambio en metadatos (permisos, dueño) | Se altera con `chmod`, `chown` |
| CR time / O Time | Creation / Birth | Fecha de creación del archivo | Disponible en EXT4, XFS y BTRFS. No existe en EXT2/3 |

## 2. Detección de "Timestomping" (Manipulación de Fechas)

Los atacantes usan `touch` para modificar fechas y ocultar malware.

### Indicadores comunes

- **Precisión de nanosegundos**  
  Si el timestamp muestra ceros exactos (ej. `.000000000`), indica manipulación manual.

- **Inconsistencias temporales**  
  Si el *Modify Time* es anterior al *Creation Time* (en Linux), es una anomalía sospechosa.

## 3. Herramientas y Características por Sistema de Archivos

| Sistema | Características Clave | Herramientas Forenses / Recuperación |
|-------|----------------------|--------------------------------------|
| EXT3 / EXT4 | Journaling (protege integridad). EXT4 usa *Extents* y timestamps precisos | TSK (`fls`, `icat`, `istat`, `jls`), `debugfs`, `ext4magic` (recupera usando el journal) |
| BTRFS | Copy on Write (COW), Snapshots y Subvolúmenes | `btrfs-restore`, `btrfs subvol list`. TSK tiene soporte limitado |
| XFS | Alto rendimiento, 64-bit | `xfs_db` (depuración), `xfs_repair`. TSK estándar no lo soporta (requiere fork) |

## 4. Recuperación de Datos (File Carving)

Cuando el sistema de archivos está dañado o se busca en espacio no asignado:

- **PhotoRec**  
  Ignora el sistema de archivos y busca *firmas* (headers/footers) de archivos conocidos como JPG, PDF u Office.


# F. Mecanismos de Persistencia y Ejecución

Rutas y técnicas utilizadas por atacantes para mantener el acceso tras un reinicio.

## 1. Servicios del Sistema

| Sistema | Ubicación de Archivos | Vector de Ataque |
|-------|----------------------|------------------|
| systemd | `/etc/systemd/system/` | Archivos `.service` maliciosos. Directivas clave: `ExecStart` (comando), `Restart=always` (revive proceso) |
| SysV Init | `/etc/init.d/` | Inyección de scripts en bloques `start`. Habilitados mediante enlaces simbólicos en runlevels |

## 2. Tareas Programadas

### Cron Jobs

- **Ubicación**
  - `/var/spool/cron/crontabs/` (usuario)
  - `/etc/cron.d/` (sistema)

- **Detección**
  - Buscar patrones `* * * * *` (ejecución cada minuto)

### Systemd Timers

- Archivos `.timer` que controlan servicios
- **Riesgo**
  - `Persistent=true` ejecuta tareas pendientes tras reiniciar
  - Un timer puede activar un servicio con nombre diferente (ofuscación)

## 3. Persistencia SSH (Claves Autorizadas)

El atacante añade su clave pública para entrar sin contraseña.

- **Archivo**
  - `~/.ssh/authorized_keys`

- **Permisos Críticos**
  - Directorio: `700` (`drwx------`)
  - Archivo: `600` (`-rw-------`)

Permisos más abiertos suelen bloquear el servicio SSH.

## 4. Otros Vectores de Ejecución

- **Shell**
  - `.bashrc`, `.bash_profile` en `/home` (se ejecutan al abrir terminal)

- **Boot**
  - `/etc/rc.local` (scripts al final del arranque)

- **Hardware (Udev)**
  - `/etc/udev/rules.d/` (reglas que ejecutan scripts al conectar un USB)

- **Entorno Gráfico**
  - `/etc/xdg/autostart/` (se ejecutan al iniciar sesión gráfica)

# G. Herramientas de Adquisición de Evidencia

Métodos para capturar discos y memoria preservando la cadena de custodia.

## 1. Adquisición de Disco (Línea de Comandos)

| Herramienta | Características | Uso Recomendado |
| :--- | :--- | :--- |
| **dd** | Estándar Unix (1974). Sin hash nativo ni barra de progreso. | Sistemas antiguos o recuperación básica. |
| **dcfldd** | Hash al vuelo (MD5/SHA). Verificación por bloques. | Cuando se requiere hash durante la copia. |
| **dc3dd** | Estándar Forense (DoD). Logs de auditoría, gestión automática de bloques, progreso visual. | Opción preferente para forense formal. |

## 2. Adquisición de Memoria Volátil (RAM)

* **Herramienta:** AVML (*Acquire Volatile Memory for Linux*) de Microsoft.
* **Ventaja:** Binario estático (no requiere instalación), compatible con `/dev/crash` y `/proc/kcore`.
* **Procedimiento:** Ejecutar como `root`. Salida compatible con formato LiME.
* **Verificación:** El tamaño del volcado debe coincidir exactamente con la RAM física.

## 3. Triaje y Live Response (UAC)

* **Herramienta:** UAC (*Unix-like Artifacts Collector*).
* **Función:** Automatiza la recolección de artefactos volátiles (procesos, red) y estáticos (logs, configs) mediante scripts nativos.
* **Salida:** Archivo `.tar.gz` conteniendo:
    * **Bodyfile:** Listado de archivos para líneas de tiempo (*timelines*).
    * **Live Response:** Salida de comandos de sistema (`netstat`, `ps`, `lsof`).
    * **Root:** Copia parcial de archivos críticos (`/etc`, `/home`).

# H. Creación y Análisis de Líneas de Tiempo (Timeline Analysis)

## 1. Metodología Clásica (The Sleuth Kit)

Proceso secuencial para convertir metadatos del disco en una hoja de cálculo analizable.

1.  **Generación (fls):** Recorre la imagen recursivamente.
    * Comando: `fls -r -m /imagen.dd > bodyfile.txt`
2.  **Normalización (mactime):** Procesa el *bodyfile*.
    * Uso de parámetros `-d` (CSV) y `-y` (ISO 8601) para estandarizar a UTC.
3.  **Análisis (Timeline Explorer):** Filtrado por columna **MACB**:
    * `deleted`: Archivo borrado recuperable.
    * `deleted-realloc`: Archivo borrado y sobrescrito.

## 2. Metodología "Super Timeline" (Plaso)

Herramienta (`log2timeline`) que integra artefactos dispares (logs, historial web, sistema de archivos) en una vista única.

* **log2timeline:** Motor (*parser*). Extrae eventos de la imagen y crea una base de datos de eventos.
* **psort:** Filtrado y ordenación. Convierte la base de datos a un formato legible (CSV/Excel).
* **psteel:** Orquestador que ejecuta la extracción y genera el reporte en un solo paso.

**Valor Forense:** Permite correlacionar eventos de distinta naturaleza, como la descarga de un archivo (Historial Web), su ejecución posterior (Bash History) y su persistencia en el sistema (Systemd).
