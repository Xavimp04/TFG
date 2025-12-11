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

## 3. VMware ESXi

Logs principales en `/var/log` del hipervisor:

- **VMkernel.log:** Actividad del kernel virtual y errores.  
- **Shell.log:** Comandos ejecutados (auditoría).  
- **Auth.log:** Autenticación en el hipervisor.
