#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "forensics.h"

void generar_reporte_completo(const char *nombre_archivo) {
    // Guardamos el stdout original para restaurarlo después
    FILE *original_stdout = stdout;
    FILE *fp = fopen(nombre_archivo, "w");

    if (fp == NULL) {
        perror(RED "    [-] Error al crear el archivo de reporte" RESET);
        return;
    }

    // Redirigimos la salida estándar al archivo (Tema 7: Automatización)
    stdout = fp;

    printf("============================================================\n");
    printf("        REPORTE FORENSE GENERADO POR FORENSICXM\n");
    printf("============================================================\n");
    
    time_t now = time(NULL);
    printf("Fecha del Análisis: %s", ctime(&now));
    
    // Ejecutamos todos los módulos definidos en la teoría
    identificar_sistema();    // Tema 3
    analizar_usuarios();      // Tema 4
    analizar_persistencia();  // Tema 6
    analizar_logs();          // Tema 4
    analizar_logins_binarios(); // Tema 4
    analizar_red();             // Tema 6 & 7

    printf("\n============================================================\n");
    printf("        FIN DEL REPORTE - INTEGRIDAD DE LA PRUEBA\n");
    printf("============================================================\n");

    fclose(fp);
    stdout = original_stdout; // Restauramos la terminal

    printf(GREEN "[+] Reporte generado con éxito: %s" RESET "\n", nombre_archivo);

    // Calculamos el hash del propio reporte para la Cadena de Custodia (Tema 7)
    char comando[1024];
    snprintf(comando, sizeof(comando), "sha256sum %s", nombre_archivo);
    printf("[*] Firma digital del reporte (SHA-256):\n    ");
    fflush(stdout);
    system(comando);
}