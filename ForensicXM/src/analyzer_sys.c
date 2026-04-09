#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "forensics.h"

void identificar_sistema() {
    FILE *fp;
    char linea[256];
    char *nombre_distro = "Desconocida";

    printf("\n--- [" GREEN "Identificación del Sistema" RESET "] ---\n");

    char path[1024];
    snprintf(path, sizeof(path), "%s/etc/os-release", root_dir);

    // Abrimos el archivo que contiene la info de la distro
    fp = fopen(path, "r");
    if (fp == NULL) {
        perror("Error al abrir /etc/os-release");
        return;
    }

    // Buscamos la línea que empieza por PRETTY_NAME
    while (fgets(linea, sizeof(linea), fp)) {
        if (strncmp(linea, "PRETTY_NAME=", 12) == 0) {
            // Limpiamos las comillas y el salto de línea
            nombre_distro = strchr(linea, '=') + 1;
            printf("[+] Distribución detectada: %s", nombre_distro);
            break;
        }
    }
    fclose(fp);

    // Eliminamos la llamada insegura system("uname -rsv")
    // En su lugar, abrimos directamente /proc/version de las estructuras del Kernel (Tema 8/Forensics)
    char proc_version_path[1024];
    snprintf(proc_version_path, sizeof(proc_version_path), "%s/proc/version", root_dir);
    
    FILE *fp_vers = fopen(proc_version_path, "r");
    if (fp_vers) {
        char version_line[512];
        if (fgets(version_line, sizeof(version_line), fp_vers)) {
            printf("[+] Información del Kernel: %s", version_line);
        }
        fclose(fp_vers);
    } else {
        printf(YELLOW "[-] Información del Kernel: No disponible (no se pudo leer %s)\n" RESET, proc_version_path);
    }
    
    printf("------------------------------------------\n");
}