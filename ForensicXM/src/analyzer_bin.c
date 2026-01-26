#include <stdio.h>
#include <utmp.h>
#include <time.h>
#include <string.h>
#include "forensics.h"

void analizar_logins_binarios() {
    struct utmp registro;
    FILE *fp;

    printf("\n--- [" GREEN "Historial de Logins Binarios (/var/log/wtmp)" RESET "] ---\n");

    // Abrimos el archivo binario wtmp (Tema 4)
    fp = fopen("/var/log/wtmp", "rb");
    if (fp == NULL) {
        perror(RED "    [-] Error al abrir /var/log/wtmp" RESET);
        return;
    }

    printf("%-15s %-15s %-20s %-20s\n", "Usuario", "Terminal", "Host", "Fecha/Hora");
    printf("--------------------------------------------------------------------------------\n");

    // Leemos el archivo registro por registro
    while (fread(&registro, sizeof(struct utmp), 1, fp) == 1) {
        // Solo mostramos registros de tipo USER_PROCESS (logins de usuario)
        if (registro.ut_type == USER_PROCESS) {
            time_t t = registro.ut_tv.tv_sec;
            char *hora = ctime(&t);
            hora[strlen(hora) - 1] = '\0'; // Quitamos el salto de línea

            printf("%-15s %-15s %-20s %-20s\n", 
                   registro.ut_user, 
                   registro.ut_line, 
                   registro.ut_host, 
                   hora);
        }
    }

    fclose(fp);
    printf("--------------------------------------------------------------------------------\n");
}