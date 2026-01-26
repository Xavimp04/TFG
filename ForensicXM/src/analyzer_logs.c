#include <stdio.h>
#include <string.h>
#include "forensics.h"

void analizar_logs() {
    FILE *fp;
    char linea[1024];
    int fallos = 0;

    printf("\n--- [" GREEN "Análisis de Logs de Autenticación" RESET "] ---\n");
    printf("[+] Buscando anomalías en /var/log/auth.log...\n");

    // Abrimos auth.log (Requiere sudo generalmente) 
    fp = fopen("/var/log/auth.log", "r");
    if (fp == NULL) {
        perror(RED "    [-] Error al abrir /var/log/auth.log (¿Has usado sudo?)" RESET);
        return;
    }

    while (fgets(linea, sizeof(linea), fp)) {
        // Buscar intentos fallidos de contraseña [cite: 238, 257]
        if (strstr(linea, "Failed password") || strstr(linea, "authentication failure")) {
            if (fallos < 10) { // Solo mostramos los primeros 10 para no inundar la terminal
                printf(RED "    [!] Intento fallido:" RESET " %s", linea);
            }
            fallos++;
        }
        
        // Buscar accesos directos de root (SOSPECHOSO si no es habitual) 
        if (strstr(linea, "session opened for user root")) {
            printf(GREEN "    [*] Sesión root abierta:" RESET " %s", linea);
        }
    }

    if (fallos > 0) {
        printf("\n" RED "[!] Alerta:" RESET " Se detectaron %d intentos de autenticación fallidos.\n", fallos);
    } else {
        printf(GREEN "    [+] No se detectaron fallos de autenticación recientes." RESET "\n");
    }

    fclose(fp);
    printf("------------------------------------------------------------\n");
}