#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include "forensics.h"

/*
 * NOTA DE VALIDACIÓN (VM0 de control):
 * El análisis de la VM0 limpia reveló que numerosos procesos legítimos de
 * escritorio (gnome-shell, gjs, nautilus, gnome-terminal...) presentan
 * regiones de memoria RWX. Esto NO es malware: los motores con compilación
 * "Just-In-Time" (el intérprete JavaScript de GNOME, navegadores, etc.)
 * necesitan páginas de memoria que sean escribibles y ejecutables a la vez
 * para generar y correr código en caliente.
 *
 * Por tanto, una región RWX por sí sola NO es un Indicador de Compromiso
 * fiable. Para reducir los falsos positivos sin perder capacidad de
 * detección, este módulo ahora ESTRATIFICA la severidad:
 *
 *   - CRÍTICO: el proceso tiene región RWX *Y ADEMÁS* corre desde un
 *              binario borrado. Esta combinación es muy característica de
 *              malware (se inyecta código y se elimina el rastro en disco).
 *   - SOSPECHA BAJA: el proceso tiene región RWX pero su binario existe
 *              en disco. Probablemente JIT legítimo; se informa para
 *              revisión manual pero sin marcarlo como alerta crítica.
 */

// Comprueba si un proceso corre desde un binario borrado.
// Devuelve 1 si el binario fue borrado, 0 si sigue en disco.
int check_deleted_binary(const char *pid, const char *proc_name) {
    char path[256];
    char buffer[1024];
    ssize_t len;

    snprintf(path, sizeof(path), "/proc/%s/exe", pid);
    len = readlink(path, buffer, sizeof(buffer) - 1);

    if (len != -1) {
        buffer[len] = '\0';
        if (strstr(buffer, " (deleted)")) {
            printf(RED "    [!] ALERTA: Proceso '%s' (PID: %s) ejecutándose desde binario borrado." RESET "\n", proc_name, pid);
            printf("        Ruta original: %s\n", buffer);
            return 1;
        }
    }
    return 0;
}

// Comprueba si un proceso tiene alguna región de memoria RWX.
// Devuelve 1 si encuentra al menos una, 0 si no.
// Solo detecta; la decisión de severidad se toma en analizar_memoria().
int check_rwx_memory(const char *pid, char *detalle_out, size_t detalle_len) {
    char path[256];
    char line[1024];
    FILE *fp;
    int encontrada = 0;

    snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    fp = fopen(path, "r");

    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            // Formato maps: address perms offset dev inode pathname
            // Los permisos son el segundo campo, ej: "rwxp"
            if (strstr(line, "rwx")) {
                encontrada = 1;
                if (detalle_out) {
                    strncpy(detalle_out, line, detalle_len - 1);
                    detalle_out[detalle_len - 1] = '\0';
                }
                break; // Una ocurrencia basta para marcar el proceso
            }
        }
        fclose(fp);
    }
    return encontrada;
}

void analizar_memoria(ForensicContext *ctx) {
    (void)ctx; // Parámetro de interfaz no usado porque lee directamente de /proc
    DIR *dir;
    struct dirent *entry;

    printf("\n--- [" GREEN "Análisis de Memoria RAM (Procesos)" RESET "] ---\n");
    
    if (geteuid() != 0) {
        printf(YELLOW "[!] Nota: Ejecuta con SUDO para analizar todos los procesos.\n" RESET);
    }

    dir = opendir("/proc");
    if (!dir) {
        perror("Error al abrir /proc");
        return;
    }

    int count_checked = 0;
    int count_critico = 0;     // RWX + binario borrado
    int count_sospecha = 0;    // RWX a secas (posible JIT)

    while ((entry = readdir(dir)) != NULL) {
        // Solo PIDs numéricos
        if (!isdigit(entry->d_name[0])) continue;

        char path_comm[PATH_MAX];
        char proc_name[256] = "Desconocido";
        
        // Obtener nombre del proceso
        snprintf(path_comm, sizeof(path_comm), "/proc/%s/comm", entry->d_name);
        FILE *fp_comm = fopen(path_comm, "r");
        if (fp_comm) {
            if (fgets(proc_name, sizeof(proc_name), fp_comm)) {
                proc_name[strcspn(proc_name, "\n")] = 0;
            }
            fclose(fp_comm);
        }

        // 1. ¿Corre desde un binario borrado?
        int binario_borrado = check_deleted_binary(entry->d_name, proc_name);

        // 2. ¿Tiene alguna región de memoria RWX?
        char detalle_rwx[512] = "";
        int tiene_rwx = check_rwx_memory(entry->d_name, detalle_rwx, sizeof(detalle_rwx));

        // 3. Decisión de severidad ESTRATIFICADA
        if (tiene_rwx && binario_borrado) {
            // Combinación altamente característica de malware inyectado
            printf(RED "    [!] ALERTA CRÍTICA: Proceso '%s' (PID: %s) combina memoria RWX con binario borrado." RESET "\n",
                   proc_name, entry->d_name);
            printf("        Detalle RWX: %s", detalle_rwx);
            count_critico++;
        } else if (tiene_rwx) {
            // RWX a secas: probablemente JIT legítimo. Se informa con
            // severidad baja para revisión manual, NO como alerta crítica.
            printf(YELLOW "    [*] Sospecha baja: Proceso '%s' (PID: %s) tiene región RWX (posible JIT legítimo, revisar)." RESET "\n",
                   proc_name, entry->d_name);
            printf("        Detalle: %s", detalle_rwx);
            count_sospecha++;
        }
        
        count_checked++;
    }

    closedir(dir);
    printf("[+] Se han analizado %d procesos en busca de anomalías en memoria.\n", count_checked);
    printf("    -> %d con severidad CRÍTICA (RWX + binario borrado)\n", count_critico);
    printf("    -> %d con sospecha baja (RWX aislado, posible JIT)\n", count_sospecha);
    if (count_critico == 0) {
        printf(GREEN "    [+] No se detectaron combinaciones críticas en memoria." RESET "\n");
    }
    printf("------------------------------------------------------------\n");
}
