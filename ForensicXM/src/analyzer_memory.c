#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include "forensics.h"

// Función para comprobar si un proceso se ejecuta desde un binario borrado
void check_deleted_binary(const char *pid, const char *proc_name) {
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
        }
    }
}

// Función para buscar regiones de memoria RWX (Lectura + Escritura + Ejecución)
void check_rwx_memory(const char *pid, const char *proc_name) {
    char path[256];
    char line[1024];
    FILE *fp;

    snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    fp = fopen(path, "r");

    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            // Buscamos la cadena "rwx" en la línea de permisos
            // Formato maps: address perms offset dev inode pathname
            // Ej: 00400000-00452000 r-xp ...
            if (strstr(line, "rwx")) {
                 printf(RED "    [!] ALERTA: Proceso '%s' (PID: %s) tiene región de memoria RWX (Sospechoso de Inyección/Shellcode)." RESET "\n", proc_name, pid);
                 printf("        Detalle: %s", line);
                 // Solo mostramos la primera ocurrencia por proceso para no inundar
                 break; 
            }
        }
        fclose(fp);
    }
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

        // 1. Chequeo de binario borrado
        check_deleted_binary(entry->d_name, proc_name);

        // 2. Chequeo de memoria RWX
        check_rwx_memory(entry->d_name, proc_name);
        
        count_checked++;
    }

    closedir(dir);
    printf("[+] Se han analizado %d procesos en busca de anomalías en memoria.\n", count_checked);
    printf("------------------------------------------------------------\n");
}
