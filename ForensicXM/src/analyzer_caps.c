#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include "forensics.h"

// Capacidades peligrosas conocidas que buscaremos
// Referencia: linux/capability.h
#define CAP_NET_RAW     13
#define CAP_SYS_ADMIN   21
#define CAP_SYS_PTRACE  23
#define CAP_SYS_MODULE  16
#define CAP_DAC_OVERRIDE 1

/**
 * @brief Comprueba si un bit específico (capacidad) está encendido en una máscara de 64 bits.
 * @param caps_mask Máscara hexadecimal de las capacidades efectivas del proceso.
 * @param cap_bit El número de bit de la capacidad a comprobar (ej. CAP_NET_RAW).
 * @return 1 si la capacidad está presente, 0 en caso contrario.
 */
static int has_capability(unsigned long long caps_mask, int cap_bit) {
    return (caps_mask & (1ULL << cap_bit)) != 0;
}

void analizar_capacidades(ForensicContext *ctx) {
    (void)ctx; // Parámetro de interfaz no usado porque lee directamente de /proc
    DIR *dir;
    struct dirent *entry;
    int sospechosos = 0;

    printf("\n--- [" GREEN "Análisis de Privilegios: Linux Capabilities" RESET "] ---\n");
    
    cJSON *caps_array = NULL;
    if (ctx->modo_json) {
        caps_array = cJSON_AddArrayToObject(ctx->json_report, "capabilities");
    } else {
        if (geteuid() != 0) {
            printf(YELLOW "[!] Nota: Ejecuta con SUDO para poder acceder a todos los procesos.\n" RESET);
        }
        printf("%-8s %-6s %-20s %-15s %s\n", "PID", "UID", "Nombre", "Peligrosidad", "Capacidades Críticas Detectadas");
        printf("--------------------------------------------------------------------------------------------------\n");
    }

    dir = opendir("/proc");
    if (!dir) {
        perror(RED "    [-] Error al abrir /proc" RESET);
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        // Solo Procesos (PIDs son números)
        if (!isdigit(entry->d_name[0])) continue;

        char path[512];
        snprintf(path, sizeof(path), "/proc/%s/status", entry->d_name);
        
        FILE *fp = fopen(path, "r");
        if (!fp) continue; // Puede haber muerto o no tener permisos

        char linea[256];
        char proc_name[64] = "Desconocido";
        int uid = -1;
        unsigned long long cap_eff = 0;
        int found_uid = 0, found_cap = 0, found_name = 0;

        while (fgets(linea, sizeof(linea), fp)) {
            if (strncmp(linea, "Name:\t", 6) == 0) {
                sscanf(linea, "Name:\t%63s", proc_name);
                found_name = 1;
            } else if (strncmp(linea, "Uid:\t", 5) == 0) {
                // El formato suele ser: Uid:    Real    Effective       Saved   Filesystem
                sscanf(linea, "Uid:\t%d", &uid);
                found_uid = 1;
            } else if (strncmp(linea, "CapEff:\t", 8) == 0) {
                // Formato: CapEff: 0000000000000000
                sscanf(linea, "CapEff:\t%llx", &cap_eff);
                found_cap = 1;
            }
            
            if (found_uid && found_cap && found_name) break; // Optimización, no leemos todo el archivo
        }
        fclose(fp);

        // REGLA FUNDAMENTAL: Buscamos Procesos que NO son ROOT pero que Tienen Capacidades
        if (uid != 0 && cap_eff > 0) {
            char cap_desc[256] = "";
            int is_critical = 0;

            if (has_capability(cap_eff, CAP_NET_RAW)) {
                strcat(cap_desc, "CAP_NET_RAW(sniffer) ");
                is_critical = 1;
            }
            if (has_capability(cap_eff, CAP_SYS_ADMIN)) {
                strcat(cap_desc, "CAP_SYS_ADMIN(escape) ");
                is_critical = 1;
            }
            if (has_capability(cap_eff, CAP_SYS_PTRACE)) {
                strcat(cap_desc, "CAP_SYS_PTRACE(inyectar) ");
                is_critical = 1;
            }
            if (has_capability(cap_eff, CAP_SYS_MODULE)) {
                strcat(cap_desc, "CAP_SYS_MODULE(rootkit) ");
                is_critical = 1;
            }
            if (has_capability(cap_eff, CAP_DAC_OVERRIDE)) {
                strcat(cap_desc, "CAP_DAC_OVERRIDE(leer_todo) ");
                is_critical = 1;
            }

            if (is_critical || !is_critical) {
                if (ctx->modo_json && caps_array) {
                    cJSON *cap_item = cJSON_CreateObject();
                    cJSON_AddNumberToObject(cap_item, "pid", atoi(entry->d_name));
                    cJSON_AddNumberToObject(cap_item, "uid", uid);
                    cJSON_AddStringToObject(cap_item, "name", proc_name);
                    
                    if (is_critical) {
                        cJSON_AddStringToObject(cap_item, "severity", "HIGH");
                        cJSON_AddStringToObject(cap_item, "capabilities", cap_desc);
                    } else {
                        char hex_caps[32];
                        snprintf(hex_caps, sizeof(hex_caps), "%llx", cap_eff);
                        cJSON_AddStringToObject(cap_item, "severity", "MODERATE");
                        cJSON_AddStringToObject(cap_item, "capabilities", hex_caps);
                    }
                    cJSON_AddItemToArray(caps_array, cap_item);
                } else {
                    if (is_critical) {
                        printf(RED "%-8s %-6d %-20s %-15s %s" RESET "\n", entry->d_name, uid, proc_name, "ALTA", cap_desc);
                    } else {
                        printf(YELLOW "%-8s %-6d %-20s %-15s %llx (bits encendidos)" RESET "\n", entry->d_name, uid, proc_name, "MODERADA", cap_eff);
                    }
                }
                sospechosos++;
            }
        }
    }
    
    closedir(dir);

    if (!ctx->modo_json) {
        if (sospechosos == 0) {
            printf(GREEN "\n    [+] No se detectaron procesos no-root con capacidades críticas." RESET "\n");
        } else {
            printf(RED "\n    [!] Advertencia: Se han detectado %d procesos con capacidades críticas." RESET "\n", sospechosos);
        }
        printf("--------------------------------------------------------------------------------------------------\n");
    }
}
