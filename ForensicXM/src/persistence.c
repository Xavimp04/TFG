#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include "forensics.h"

// Función para buscar strings maliciosos dentro de los archivos (Tema 6)
void escanear_contenido_sospechoso(const char *ruta_archivo) {
    FILE *fp = fopen(ruta_archivo, "r");
    if (!fp) return;

    char linea[512];
    char *sospechosos[] = {"curl", "wget", "nc ", "python", "perl", "bash -i"};
    int num_sospechosos = 6;

    while (fgets(linea, sizeof(linea), fp)) {
        for (int i = 0; i < num_sospechosos; i++) {
            if (strstr(linea, sospechosos[i])) {
                printf(RED "      [!] Alerta: Comando sospechoso '%s' encontrado en el contenido." RESET "\n", sospechosos[i]);
                printf("          Línea: %s", linea);
            }
        }
    }
    fclose(fp);
}

void listar_directorio_persistencia(const char *ruta, const char *descripcion) {
    struct dirent *entry;
    DIR *dp = opendir(ruta);

    printf("\n[+] Revisando %s (%s)...\n", descripcion, ruta);
    
    if (dp == NULL) {
        printf(RED "    [-] No se pudo acceder a %s" RESET "\n", ruta);
        return;
    }

    while ((entry = readdir(dp))) {
        if (entry->d_name[0] == '.') continue;
        
        printf("    -> Analizando: %s\n", entry->d_name);
        
        // Construimos la ruta completa para abrir el archivo
        char ruta_completa[1024];
        snprintf(ruta_completa, sizeof(ruta_completa), "%s/%s", ruta, entry->d_name);
        
        // Solo escaneamos si es un archivo regular (no una carpeta .wants)
        if (entry->d_type == DT_REG) {
            escanear_contenido_sospechoso(ruta_completa);
        }
    }
    closedir(dp);
}

void analizar_persistencia() {
    printf("\n--- [" GREEN "Análisis de Persistencia y Contenido" RESET "] ---\n");

    // Revisión de Cron (Tema 6)
    listar_directorio_persistencia("/etc/cron.d", "Tareas Cron");
    
    // Revisión de Systemd (Tema 6)
    listar_directorio_persistencia("/etc/systemd/system", "Servicios Systemd");

    printf("\n------------------------------------------------------------\n");
}