#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include "forensics.h"

// Función auxiliar genérica para calcular SHA-256 (Reemplaza a system("sha256sum"))
void calcular_sha256_archivo(const char *ruta) {
    FILE *file = fopen(ruta, "rb");
    if (!file) {
        printf(RED "Error al abrir %s para calcular hash.\n" RESET, ruta);
        return;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if(mdctx == NULL) {
        fclose(file);
        return;
    }

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    const int bufSize = 32768; // 32KB
    unsigned char *buffer = malloc(bufSize);
    size_t bytesRead = 0;

    if (!buffer) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return;
    }

    while ((bytesRead = fread(buffer, 1, bufSize, file))) {
        EVP_DigestUpdate(mdctx, buffer, bytesRead);
    }

    EVP_DigestFinal_ex(mdctx, hash, &lengthOfHash);
    
    EVP_MD_CTX_free(mdctx);
    fclose(file);
    free(buffer);

    // Imprimir el hash en formato hexadecimal
    for (unsigned int i = 0; i < lengthOfHash; i++) {
        printf("%02x", hash[i]);
    }
    printf("  %s\n", ruta);
}

void generar_reporte_completo(const char *nombre_archivo) {
    // Guardamos el stdout original (File Descriptor 1) para restaurarlo después
    int saved_stdout = dup(STDOUT_FILENO);
    FILE *fp = fopen(nombre_archivo, "w");

    if (fp == NULL) {
        perror(RED "    [-] Error al crear el archivo de reporte" RESET);
        close(saved_stdout);
        return;
    }

    // Redirigimos la salida estándar al archivo a nivel de SO (dup2)
    fflush(stdout); // Aseguramos que no haya datos pendientes antes de redirigir
    dup2(fileno(fp), STDOUT_FILENO);

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
    if (!modo_deadbox) {
        analizar_red();             // Tema 6 & 7
        analizar_memoria();         // Tema 6 (Malware volatile)
        analizar_rootkits();        // Tema 6 (LKM Rootkits)
        analizar_capacidades();     // Tema 4 (Privilegios/Caps)
    } else {
        printf("\n============================================================\n");
        printf("        MODO DEADBOX: Análisis de Red y Memoria omitidos\n");
        printf("============================================================\n");
    }

    printf("\n============================================================\n");
    printf("        FIN DEL REPORTE - INTEGRIDAD DE LA PRUEBA\n");
    printf("============================================================\n");

    fflush(stdout);
    fclose(fp);
    dup2(saved_stdout, STDOUT_FILENO); // Restauramos la terminal
    close(saved_stdout);

    printf(GREEN "[+] Reporte generado con éxito: %s" RESET "\n", nombre_archivo);

    // Calculamos el hash del propio reporte para la Cadena de Custodia (Tema 7)
    printf("[*] Firma digital del reporte (SHA-256):\n    ");
    calcular_sha256_archivo(nombre_archivo);
}