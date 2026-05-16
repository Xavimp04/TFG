#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include "forensics.h"

/*
 * NOTA DE VALIDACIÓN (VM0 + VM2):
 *
 * El análisis de la VM0 reveló que numerosos procesos legítimos de
 * escritorio (gnome-shell, gjs, nautilus...) presentan regiones de
 * memoria RWX por uso de compilación Just-In-Time. Para no descartar
 * la detección, este módulo estratifica la severidad en dos niveles:
 *
 *   - CRÍTICO: RWX + binario borrado. Combinación característica de
 *              malware inyectado en memoria.
 *   - SOSPECHA BAJA: RWX sin borrado. Probable JIT legítimo;
 *              revisión manual sin alerta crítica.
 *
 * Además, el análisis de la VM2 destapó un defecto adicional en la
 * detección de regiones RWX: el original usaba strstr(line, "rwx"),
 * que matchea la subcadena en cualquier parte de la línea, incluido
 * el nombre del fichero mapeado. Cuando un binario llamado p.ej.
 * "rwx_proc" se mapea en memoria, su mapeo del segmento de código
 * (con permisos r--p) contiene la cadena "rwx" en el campo path y
 * generaba un falso emparejamiento, distorsionando el detalle
 * mostrado en el reporte. La corrección extrae explícitamente el
 * campo de permisos (segundo campo del formato de /proc/[pid]/maps)
 * y compara exactamente con "rwx".
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

// Comprueba si un proceso tiene alguna región de memoria con permisos
// EXACTAMENTE "rwx" (lectura + escritura + ejecución).
// Devuelve 1 si encuentra al menos una, 0 si no.
//
// CORRECCIÓN VM2: el formato de /proc/[pid]/maps es
//     address           perms offset  dev   inode  pathname
//     7f1234567000-...  rwxp  00000000 fd:01 12345  /ruta/al/binario
// El campo de permisos siempre es el segundo, separado por espacios.
// Se parsea posicionalmente para evitar falsos emparejamientos cuando
// la subcadena "rwx" aparece en el nombre del binario (ej: rwx_proc).
int check_rwx_memory(const char *pid, char *detalle_out, size_t detalle_len) {
    char path[256];
    char line[1024];
    FILE *fp;
    int encontrada = 0;

    snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    fp = fopen(path, "r");

    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            // Extraemos el campo de permisos: tras el primer espacio,
            // los siguientes 4 caracteres (p.ej. "rwxp" o "r-xp").
            char *sp = strchr(line, ' ');
            if (!sp || strlen(sp) < 5) continue;

            // perms apunta a 4 caracteres exactos
            char *perms = sp + 1;

            // Necesitamos r, w y x simultáneos en sus posiciones
            if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
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
    (void)ctx;
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
    int count_critico = 0;
    int count_sospecha = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;

        char path_comm[PATH_MAX];
        char proc_name[256] = "Desconocido";

        snprintf(path_comm, sizeof(path_comm), "/proc/%s/comm", entry->d_name);
        FILE *fp_comm = fopen(path_comm, "r");
        if (fp_comm) {
            if (fgets(proc_name, sizeof(proc_name), fp_comm)) {
                proc_name[strcspn(proc_name, "\n")] = 0;
            }
            fclose(fp_comm);
        }

        int binario_borrado = check_deleted_binary(entry->d_name, proc_name);

        char detalle_rwx[512] = "";
        int tiene_rwx = check_rwx_memory(entry->d_name, detalle_rwx, sizeof(detalle_rwx));

        if (tiene_rwx && binario_borrado) {
            printf(RED "    [!] ALERTA CRÍTICA: Proceso '%s' (PID: %s) combina memoria RWX con binario borrado." RESET "\n",
                   proc_name, entry->d_name);
            printf("        Detalle RWX: %s", detalle_rwx);
            count_critico++;
        } else if (tiene_rwx) {
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
