# Apéndice: Referencia Técnica de Arquitectura y Forense en Linux

Este apéndice recopila las estructuras de directorios.

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
