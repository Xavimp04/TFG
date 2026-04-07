#define _GNU_SOURCE
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/stat.h>
#include "forensics.h"

void verificar_integridad(const char *ruta) {
    struct statx stx;

    printf("\n--- [" GREEN "Análisis de Integridad y Metadatos (MACB)" RESET "] ---\n");
    printf("[+] Analizando: %s\n", ruta);

    if (syscall(SYS_statx, AT_FDCWD, ruta, AT_SYMLINK_NOFOLLOW, STATX_ALL, &stx) == -1) {
        perror(RED "    [-] Error al acceder al archivo (statx falló)" RESET);
        return;
    }

    // 1. Mostrar información básica (Tema 5)
    printf("    -> Tamaño: %llu bytes\n", (unsigned long long)stx.stx_size);
    printf("    -> Inodo:  %llu\n", (unsigned long long)stx.stx_ino);
    printf("    -> UID/GID: %d / %d\n", stx.stx_uid, stx.stx_gid);

    // 2. Mostrar sellos de tiempo (Tema 5: MACB)
    char mtime[24], atime[24], ctime[24], btime[24];
    
    time_t t_mtime = stx.stx_mtime.tv_sec;
    time_t t_atime = stx.stx_atime.tv_sec;
    time_t t_ctime = stx.stx_ctime.tv_sec;
    
    strftime(mtime, 24, "%Y-%m-%d %H:%M:%S", localtime(&t_mtime));
    strftime(atime, 24, "%Y-%m-%d %H:%M:%S", localtime(&t_atime));
    strftime(ctime, 24, "%Y-%m-%d %H:%M:%S", localtime(&t_ctime));

    printf("\n    [Sellos de Tiempo Forense (MACB)]\n");
    printf("    -> Modificación (M): %s\n", mtime);
    printf("    -> Acceso (A):       %s\n", atime);
    printf("    -> Cambio Inodo (C): %s\n", ctime);

    // Comprobamos si el Birth Time está soportado por el FS
    if (stx.stx_mask & STATX_BTIME) {
        time_t t_btime = stx.stx_btime.tv_sec;
        strftime(btime, 24, "%Y-%m-%d %H:%M:%S", localtime(&t_btime));
        printf("    -> Nacimiento (B):   %s\n", btime);
        
        // Detección de Timestomping más precisa (M anterior a B)
        if (stx.stx_mtime.tv_sec < stx.stx_btime.tv_sec) {
            printf(RED "    [!] ALERTA CRÍTICA: Timestomping detectado (Modificación anterior a Creación)." RESET "\n");
        }
    } else {
        printf("    -> Nacimiento (B):   " YELLOW "No soportado por el sistema de archivos" RESET "\n");
    }

    // Detección de Timestomping secundaria (nanosegundos a cero)
    if (stx.stx_mtime.tv_nsec == 0 && stx.stx_atime.tv_nsec == 0) {
        printf(RED "    [!] ALERTA: Timestomping posible (Nanosegundos borrados)." RESET "\n");
    }

    // 3. Calcular Hash SHA-256 (Tema 7)
    printf("\n    [Firma Digital]\n");
    printf("    -> ");
    calcular_sha256_archivo(ruta);

    printf("------------------------------------------------------------\n");
}