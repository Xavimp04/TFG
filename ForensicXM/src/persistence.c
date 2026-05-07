#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include "forensics.h"

/**
 * @brief Busca strings maliciosos conocidos dentro de un archivo.
 * @param ruta_archivo Ruta completa del archivo a escanear.
 */
static void escanear_contenido_sospechoso(const char *ruta_archivo) {
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

/**
 * @brief Recorre un directorio buscando archivos de persistencia y los escanea.
 * @param ruta Ruta del directorio a listar.
 * @param descripcion Descripción legible del tipo de persistencia analizada.
 * @param silent_fail Si es 1, no imprime error en caso de que el directorio no exista.
 */
static void listar_directorio_persistencia(const char *ruta, const char *descripcion, int silent_fail) {
    struct dirent *entry;
    DIR *dp = opendir(ruta);

    if (dp == NULL) {
        if (!silent_fail) {
            printf(RED "    [-] No se pudo acceder a %s" RESET "\n", ruta);
        }
        return;
    }

    printf("\n[+] Revisando %s (%s)...\n", descripcion, ruta);

    while ((entry = readdir(dp))) {
        if (entry->d_name[0] == '.') continue;
        
        printf("    -> Analizando: %s\n", entry->d_name);
        
        // Construimos la ruta completa para abrir el archivo
        char ruta_completa[PATH_MAX];
        snprintf(ruta_completa, sizeof(ruta_completa), "%s/%s", ruta, entry->d_name);
        
        // Solo escaneamos si es un archivo regular (no una carpeta .wants)
        if (entry->d_type == DT_REG) {
            escanear_contenido_sospechoso(ruta_completa);
        }
    }
    closedir(dp);
}

void analizar_persistencia(ForensicContext *ctx) {
    printf("\n--- [" GREEN "Análisis de Persistencia y Contenido" RESET "] ---\n");

    char path_cron[PATH_MAX], path_systemd[PATH_MAX];
    snprintf(path_cron, sizeof(path_cron), "%s/etc/cron.d", ctx->root_dir);
    snprintf(path_systemd, sizeof(path_systemd), "%s/etc/systemd/system", ctx->root_dir);

    // Revisión de Cron Global 
    listar_directorio_persistencia(path_cron, "Tareas Cron (Global)", 0);
    
    // Revisión de Cron de Usuarios
    char path_user_cron[PATH_MAX];
    snprintf(path_user_cron, sizeof(path_user_cron), "%s/var/spool/cron/crontabs", ctx->root_dir);
    listar_directorio_persistencia(path_user_cron, "Tareas Cron (Usuarios)", 1);

    // Revisión de Systemd Global
    listar_directorio_persistencia(path_systemd, "Servicios Systemd (Global)", 0);

    // Revisión de Systemd de Usuarios (Localizados en /home/*/.config/systemd/user)
    char path_home[PATH_MAX];
    snprintf(path_home, sizeof(path_home), "%s/home", ctx->root_dir);
    DIR *dp_home = opendir(path_home);
    if (dp_home) {
        struct dirent *entry_home;
        while ((entry_home = readdir(dp_home))) {
            if (entry_home->d_name[0] == '.') continue;
            if (entry_home->d_type == DT_DIR) {
                char path_user_systemd[PATH_MAX];
                snprintf(path_user_systemd, sizeof(path_user_systemd), "%s/home/%s/.config/systemd/user", ctx->root_dir, entry_home->d_name);
                
                char desc[512];
                snprintf(desc, sizeof(desc), "Systemd Units (Usu %s)", entry_home->d_name);
                // La función de persistencia ya maneja el fallo silencioso
                listar_directorio_persistencia(path_user_systemd, desc, 1);
            }
        }
        closedir(dp_home);
    }
    
    // Y verificamos el systemd user del usuario ROOT también
    char path_root_systemd[PATH_MAX];
    snprintf(path_root_systemd, sizeof(path_root_systemd), "%s/root/.config/systemd/user", ctx->root_dir);
    listar_directorio_persistencia(path_root_systemd, "Systemd Units (Root User)", 1);

    printf("\n------------------------------------------------------------\n");
}