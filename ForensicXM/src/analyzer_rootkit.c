#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include "forensics.h"

#define MAX_MODULES 1024
#define MOD_NAME_LEN 128

// Array para guardar los nombres de los módulos listados en /proc/modules
char proc_modules[MAX_MODULES][MOD_NAME_LEN];
int proc_modules_count = 0;

// Lee /proc/modules y guarda los nombres encontrados
void preload_proc_modules() {
    FILE *fp;
    char linea[512];
    
    fp = fopen("/proc/modules", "r");
    if (!fp) {
        perror(RED "    [-] Error al abrir /proc/modules" RESET);
        return;
    }

    proc_modules_count = 0;
    while (fgets(linea, sizeof(linea), fp) && proc_modules_count < MAX_MODULES) {
        char mod_name[MOD_NAME_LEN];
        // La primera palabra de cada línea es el nombre del módulo
        if (sscanf(linea, "%127s", mod_name) == 1) {
            strncpy(proc_modules[proc_modules_count], mod_name, MOD_NAME_LEN - 1);
            proc_modules[proc_modules_count][MOD_NAME_LEN - 1] = '\0';
            proc_modules_count++;
        }
    }
    fclose(fp);
}

// Verifica si un módulo existe en nuestro array extraído de /proc/modules
int is_module_in_proc(const char *mod_name) {
    for (int i = 0; i < proc_modules_count; i++) {
        // En sysfs los guiones pueden aparecer como barras bajas y viceversa, o ser exactos.
        // Hacemos una comparación estricta primero.
        if (strcmp(proc_modules[i], mod_name) == 0) {
            return 1;
        }
    }
    return 0; // No encontrado
}

// Analiza ambas fuentes y busca inconsistencias
void analizar_rootkits() {
    DIR *dir;
    struct dirent *entry;
    int sospechosos = 0;

    printf("\n--- [" GREEN "Análisis Avanzado: Detección de Rootkits LKM" RESET "] ---\n");
    
    cJSON *rk_array = NULL;
    if (modo_json) {
        rk_array = cJSON_AddArrayToObject(json_report, "rootkits");
    } else {
        if (geteuid() != 0) {
            printf(YELLOW "[!] Nota: Algunas lecturas del Kernel pueden requerir SUDO.\n" RESET);
        }
        printf("[+] Validando módulos cruzando /proc/modules con /sys/module/...\n");
    }

    // 1. Cargar la vista "High-Level" (lo que verían lsmod y las herramientas estándar)
    preload_proc_modules();
    if (proc_modules_count == 0) {
        printf(RED "    [-] No se pudo cargar la lista de módulos o está vacía.\n" RESET);
        // Continuamos de todas formas en testing
    }
    // printf("    -> Módulos reportados en /proc/modules: %d\n", proc_modules_count);

    // 2. Cargar la vista "Low-Level" (internos de sysfs)
    dir = opendir("/sys/module");
    if (!dir) {
        perror(RED "    [-] Error al abrir /sys/module" RESET);
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        char sys_mod_name[MOD_NAME_LEN];
        strncpy(sys_mod_name, entry->d_name, MOD_NAME_LEN - 1);
        sys_mod_name[MOD_NAME_LEN - 1] = '\0';

        // COMPROBACIÓN CRÍTICA: Ignorar built-in modules
        // Los módulos cargables dinámicamente suelen tener un archivo 'initstate'
        // Si no lo tiene, asumimos que está incrustado en el kernel y no nos preocupa por ahora.
        char initstate_path[512];
        snprintf(initstate_path, sizeof(initstate_path), "/sys/module/%s/initstate", sys_mod_name);
        if (access(initstate_path, F_OK) != 0) {
            continue; // No es un módulo LKM (Loadable Kernel Module) normal, lo ignoramos.
        }

        // 3. El módulo es cargable. ¿Apareció en /proc/modules?
        if (!is_module_in_proc(sys_mod_name)) {
            // Posible falso positivo por culpa de guiones vs barras bajas (ej. cfg80211)
            // Reemplazamos barras bajas por guiones en sysfs_name y comprobamos de nuevo
            char sys_mod_name_dash[MOD_NAME_LEN];
            strcpy(sys_mod_name_dash, sys_mod_name);
            for (int i=0; sys_mod_name_dash[i]; i++) {
                if (sys_mod_name_dash[i] == '-') sys_mod_name_dash[i] = '_';
            }
            if(!is_module_in_proc(sys_mod_name_dash)){
                if (modo_json && rk_array) {
                    cJSON *rk_item = cJSON_CreateObject();
                    cJSON_AddStringToObject(rk_item, "hidden_module", entry->d_name);
                    cJSON_AddStringToObject(rk_item, "severity", "CRITICAL");
                    cJSON_AddItemToArray(rk_array, rk_item);
                } else {
                    printf(RED "    [!] ALERTA CRÍTICA: Módulo Oculto Detectado: '%s'" RESET "\n", entry->d_name);
                    printf("        -> Existe en sysfs pero está siendo ocultado de /proc/modules.\n");
                }
                sospechosos++;
            }
        }
    }
    
    closedir(dir);

    if (!modo_json) {
        if (sospechosos == 0) {
            printf(GREEN "    [+] Análisis limpio. No se detectaron discrepancias de módulos." RESET "\n");
        } else {
            printf(RED "\n[!] Advertencia: Se han detectado %d posibles rootkits." RESET "\n", sospechosos);
        }
        printf("------------------------------------------------------------\n");
    }
}
