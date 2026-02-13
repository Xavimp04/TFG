#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <stdlib.h>
#include "forensics.h"

void verificar_integridad(const char *ruta) {
    struct stat st;

    printf("\n--- [" GREEN "Análisis de Integridad y Metadatos" RESET "] ---\n");
    printf("[+] Analizando: %s\n", ruta);

    if (stat(ruta, &st) == -1) {
        perror(RED "    [-] Error al acceder al archivo" RESET);
        return;
    }

    // 1. Mostrar información básica (Tema 5)
    printf("    -> Tamaño: %ld bytes\n", st.st_size);
    printf("    -> Inodo:  %ld\n", st.st_ino);
    printf("    -> UID/GID: %d / %d\n", st.st_uid, st.st_gid);

    // 2. Mostrar sellos de tiempo (Tema 5: MACB)
    char mtime[24], atime[24], ctime[24];
    strftime(mtime, 24, "%Y-%m-%d %H:%M:%S", localtime(&st.st_mtime));
    strftime(atime, 24, "%Y-%m-%d %H:%M:%S", localtime(&st.st_atime));
    strftime(ctime, 24, "%Y-%m-%d %H:%M:%S", localtime(&st.st_ctime));

    printf("\n    [Sellos de Tiempo]\n");
    printf("    -> Modificación (M): %s\n", mtime);
    printf("    -> Acceso (A):       %s\n", atime);
    printf("    -> Cambio Inodo (C): %s\n", ctime);

    // Detección de anomalías de Timestomping (Tema 5)
    if (st.st_mtim.tv_nsec == 0 && st.st_atim.tv_nsec == 0) {
        printf(RED "    [!] ALERTA: Posible Timestomping detectado (Nanosegundos en cero)." RESET "\n");
    }

    // 3. Calcular Hash SHA-256 (Tema 7)
    printf("\n    [Firma Digital]\n");
    char comando[1024];
    snprintf(comando, sizeof(comando), "sha256sum %s", ruta);
    printf("    -> ");
    fflush(stdout);
    system(comando);

    printf("------------------------------------------------------------\n");
}