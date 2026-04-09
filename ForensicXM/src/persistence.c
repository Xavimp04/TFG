#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
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

    char path_cron[1024], path_systemd[1024];
    snprintf(path_cron, sizeof(path_cron), "%s/etc/cron.d", root_dir);
    snprintf(path_systemd, sizeof(path_systemd), "%s/etc/systemd/system", root_dir);

    // Revisión de Cron Global (Tema 6)
    listar_directorio_persistencia(path_cron, "Tareas Cron (Global)");
    
    // Revisión de Cron de Usuarios
    char path_user_cron[1024];
    snprintf(path_user_cron, sizeof(path_user_cron), "%s/var/spool/cron/crontabs", root_dir);
    if (access(path_user_cron, F_OK) == 0) {
        listar_directorio_persistencia(path_user_cron, "Tareas Cron (Usuarios)");
    }

    // Revisión de Systemd Global (Tema 6)
    listar_directorio_persistencia(path_systemd, "Servicios Systemd (Global)");

    // Revisión de Systemd de Usuarios (Localizados en /home/*/.config/systemd/user)
    char path_home[1024];
    snprintf(path_home, sizeof(path_home), "%s/home", root_dir);
    DIR *dp_home = opendir(path_home);
    if (dp_home) {
        struct dirent *entry_home;
        while ((entry_home = readdir(dp_home))) {
            if (entry_home->d_name[0] == '.') continue;
            if (entry_home->d_type == DT_DIR) {
                char path_user_systemd[1024];
                snprintf(path_user_systemd, sizeof(path_user_systemd), "%s/home/%s/.config/systemd/user", root_dir, entry_home->d_name);
                
                // Evitamos imprimir error si la ruta no existe para mantener la salida limpia
                if (access(path_user_systemd, R_OK) == 0) {
                    char desc[256];
                    snprintf(desc, sizeof(desc), "Systemd Units (Usu %s)", entry_home->d_name);
                    listar_directorio_persistencia(path_user_systemd, desc);
                }
            }
        }
        closedir(dp_home);
    }
    
    // Y verificamos el systemd user del usuario ROOT también
    char path_root_systemd[1024];
    snprintf(path_root_systemd, sizeof(path_root_systemd), "%s/root/.config/systemd/user", root_dir);
    if (access(path_root_systemd, R_OK) == 0) {
        listar_directorio_persistencia(path_root_systemd, "Systemd Units (Root User)");
    }

    printf("\n------------------------------------------------------------\n");
}