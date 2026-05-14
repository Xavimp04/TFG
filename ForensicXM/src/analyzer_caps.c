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
        // CORRECCIÓN (validación VM0): se leen los CUATRO uids de /proc/[pid]/status.
        // La línea tiene el formato:  Uid:  Real  Effective  Saved  Filesystem
        // El bug anterior leía solo el Real UID, lo que provocaba que procesos
        // como 'sudo' (Real=1000, Effective=0) o binarios SUID como 'fusermount3'
        // se marcasen como "proceso no-root con capacidades robadas" cuando en
        // realidad SÍ son root de facto. La regla forense correcta debe basarse
        // en el Effective UID, que es el que determina los privilegios reales.
        int uid_real = -1, uid_eff = -1, uid_saved = -1, uid_fs = -1;
        unsigned long long cap_eff = 0;
        int found_uid = 0, found_cap = 0, found_name = 0;

        while (fgets(linea, sizeof(linea), fp)) {
            if (strncmp(linea, "Name:\t", 6) == 0) {
                sscanf(linea, "Name:\t%63s", proc_name);
                found_name = 1;
            } else if (strncmp(linea, "Uid:\t", 5) == 0) {
                // Leemos los 4 campos: Real, Effective, Saved, Filesystem
                sscanf(linea, "Uid:\t%d\t%d\t%d\t%d",
                       &uid_real, &uid_eff, &uid_saved, &uid_fs);
                found_uid = 1;
            } else if (strncmp(linea, "CapEff:\t", 8) == 0) {
                // Formato: CapEff: 0000000000000000
                sscanf(linea, "CapEff:\t%llx", &cap_eff);
                found_cap = 1;
            }
            
            if (found_uid && found_cap && found_name) break; // Optimización, no leemos todo el archivo
        }
        fclose(fp);

        // REGLA FUNDAMENTAL (corregida): un proceso es "no root" solo si NINGUNO
        // de sus uids reales/efectivos/guardados es 0. Si cualquiera es 0, el
        // proceso puede recuperar privilegios de root y sus capabilities no son
        // un indicador de compromiso. Esto elimina los falsos positivos de
        // 'sudo', 'su', 'pkexec' y binarios SUID detectados en la VM0 de control.
        int es_root_de_facto = (uid_real == 0 || uid_eff == 0 || uid_saved == 0);

        if (!es_root_de_facto && cap_eff > 0) {
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

            // CORRECCIÓN (validación VM0): el bloque anterior usaba
            //   if (is_critical || !is_critical)
            // que es SIEMPRE verdadero, por lo que la rama "MODERADA" reportaba
            // todos los procesos con cualquier capability (dbus-daemon, etc.).
            // Ahora solo se reportan procesos con capabilities REALMENTE críticas.
            if (is_critical) {
                if (ctx->modo_json && caps_array) {
                    cJSON *cap_item = cJSON_CreateObject();
                    cJSON_AddNumberToObject(cap_item, "pid", atoi(entry->d_name));
                    cJSON_AddNumberToObject(cap_item, "uid_real", uid_real);
                    cJSON_AddNumberToObject(cap_item, "uid_effective", uid_eff);
                    cJSON_AddStringToObject(cap_item, "name", proc_name);
                    cJSON_AddStringToObject(cap_item, "severity", "HIGH");
                    cJSON_AddStringToObject(cap_item, "capabilities", cap_desc);
                    cJSON_AddItemToArray(caps_array, cap_item);
                } else {
                    printf(RED "%-8s %-6d %-20s %-15s %s" RESET "\n",
                           entry->d_name, uid_eff, proc_name, "ALTA", cap_desc);
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
