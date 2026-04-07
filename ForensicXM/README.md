# ForensicXM

**ForensicXM** es una herramienta modular de Análisis Forense para sistemas Linux, desarrollada nativamente en C. Su objetivo principal es automatizar la extracción de evidencias y la detección de anomalías avanzadas o posibles compromisos de seguridad (malware, intrusiones, persistencia, inyecciones en memoria, etc.) en un sistema.

## Características Profesionales Integradas

ForensicXM soporta dos metodologías clave de análisis forense:

*   **Live Forensics (Análisis en Vivo):** Escanea el sistema actual buscando anomalías volátiles y no volátiles, como inyecciones en la memoria RAM, conexiones de red sospechosas, procesos con capacidades excesivas, rootkits LKM y usuarios anómalos.
*   **Deadbox Forensics (Análisis Post-Mortem):** Permite analizar una imagen de disco o un sistema de archivos montado estableciendo la opción `-d`. En este modo, se deshabilitan automáticamente los análisis que requieren un sistema en ejecución para preservar la integridad de la prueba.

### Módulos Analíticos Destacados:
- **Detección de Rootkits LKM:** Algoritmo de *Cross-View Validation* para comparar las tablas formales de `/proc/modules` frente a la infraestructura interna del kernel en `/sys/module`.
- **Análisis de Privilegios (Linux Capabilities):** Detección heurística de técnicas Post-Explotación, escaneando procesos sin permisos de root que secuestran capacidades críticas como `CAP_SYS_ADMIN`, `CAP_NET_RAW` o `CAP_SYS_PTRACE`.
- **Mapeo de Sockets de Red en Memoria:** Algoritmo en `O(1)` tras carga precargada de *inodes* del kernel para mapear los propietarios PID de las conexiones TCP/UDP.
- **Timelining MACB Completo:** Integración de la llamada de bajo nivel `SYS_statx` (kernel 4.11+) para extraer en sistemas ext4/btrfs la escurridiza fecha de "*Nacimiento/Creación* (Birth Time/crtime)", alertando automáticamente sobre indicios de *Timestomping*.
- **Integridad Segura:** Uso de arquitecturas POSIX nativas y APIs criptográficas modernas (OpenSSL EVP) evitando llamadas vulnerables vía `system()`.

## Requisitos y Compilación

Para compilar el proyecto, necesitas tener `gcc`, `make` y las cabeceras de desarrollo de OpenSSL (`libssl-dev` o equivalente).

1. Clona o descarga el repositorio del proyecto.
2. Abre una terminal en la raíz del proyecto.
3. Ejecuta el comando `make` para compilar el código fuente.

```bash
make
```

Esto generará un directorio `bin/` con el ejecutable `forensicXM`. Si deseas eliminar los archivos compilados, usa `make clean`.

## Uso

Debido a que la herramienta lee estructuras del kernel y archivos protegidos (`/proc/[pid]/mem`, `/etc/shadow`), **debe ejecutarse con privilegios de superusuario (`sudo`)**.

### Sintaxis básica

```bash
sudo ./bin/forensicXM [OPCIONES]
```

### Opciones Disponibles

Puedes utilizar una o varias opciones simultáneamente para realizar múltiples análisis en una sola ejecución.

*   `-v, --version`: Muestra la versión de la herramienta y la distribución del sistema.
*   `-u, --users`: Analiza los usuarios del sistema (busca backdoors, uids 0 ocultos o cuentas sin contraseña).
*   `-p, --persist`: Busca mecanismos de persistencia instalados (cronjobs, servicios systemd, scripts).
*   `-l, --logs`: Analiza los registros del sistema buscando eventos anómalos (ej. pautas de fuerza bruta).
*   `-b, --bin`: Revisa archivos binarios y registros de inicio de sesión wtmp/btmp sospechosos.
*   `-n, --net`: Analiza las conexiones de red, puertos a la escucha e interfaces en modo promiscuo (cruce rápido Inode -> PID -> Nombre).
*   `-m, --mem`: Escanea procesos en la memoria buscando inyecciones (ej. regiones RWX o procesos sin respaldo de disco).
*   `-c, --caps`: Analiza las Capabilities de Linux buscando privilegios robados en procesos "no root".
*   `-k, --root`: Detecta Rootkits *Loadable Kernel Modules* que ocultan su presencia al administrador.
*   `-j, --json`: Exporta los resultados de los módulos analíticos (Red, Capacidades, Rootkits) formateados nativamente en **JSON estructurado** para consumo por un SIEM (Elk/Splunk), a través de la librería `cJSON`.
*   `-d, --deadbox <ruta>`: Activa el modo *Deadbox* apuntando a la ruta indicada (ej. `-d /mnt/evidencia_disco_1`). **Nota:** Deshabilita los módulos dependientes de ejecución en vivo `-n`, `-m`, `-c` y `-k`.
*   `-i, --integrity <ruta>`: Muestra metadatos MACB y verifica la integridad estática de los archivos vía firmas criptográficas SHA-256 integradas con OpenSSL.
*   `-r, --report <nombre>`: Genera la batería entera de analíticas del sistema y redirecciona robustamente la información en un reporte textual sellado criptográficamente en el archivo indicado.

## Ejemplos de Ejecución

**Ejemplo 1: Exportación técnica para Integración SIEM (JSON)**
```bash
sudo ./bin/forensicXM -n -c -k -j
```

**Ejemplo 2: Análisis completo al vuelo (Live Forensics)**
```bash
sudo ./bin/forensicXM -n -m -c -k -p -b
```

**Ejemplo 3: Análisis Forense Deadbox de una imagen montada y volcado seguro a reporte**
```bash
sudo ./bin/forensicXM -d /mnt/evidencia_disco_1 -r reporte_disco_1.txt
```
