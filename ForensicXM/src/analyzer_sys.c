#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "forensics.h"

void identificar_sistema() {
    FILE *fp;
    char linea[256];
    char *nombre_distro = "Desconocida";

    printf("\n--- [" GREEN "Identificación del Sistema" RESET "] ---\n");

    // Abrimos el archivo que contiene la info de la distro
    fp = fopen("/etc/os-release", "r");
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

    // También es útil saber la versión del Kernel (La base según tu teoría)
    // Usamos una llamada simple al sistema para este ejemplo inicial
    printf("[+] Información del Kernel: ");
    fflush(stdout); // Asegura que el texto anterior se imprima antes
    system("uname -rsv"); 
    
    printf("------------------------------------------\n");
}