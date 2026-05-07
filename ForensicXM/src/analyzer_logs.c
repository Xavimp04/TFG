#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include "forensics.h"

void analizar_logs(ForensicContext *ctx) {
    FILE *fp;
    char linea[1024];
    int fallos = 0;

    printf("\n--- [" GREEN "Análisis de Logs de Autenticación" RESET "] ---\n");
    printf("[+] Buscando anomalías en /var/log/auth.log...\n");

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/var/log/auth.log", ctx->root_dir);

    // Intentamos auth.log (Debian/Ubuntu)
    fp = fopen(path, "r");
    if (fp == NULL) {
        // Fallback a secure (RHEL/CentOS/Fedora)
        snprintf(path, sizeof(path), "%s/var/log/secure", ctx->root_dir);
        fp = fopen(path, "r");
    }

    if (fp == NULL) {
        printf(RED "    [-] Error al abrir logs de autenticación (¿Has usado sudo?)\n" RESET);
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