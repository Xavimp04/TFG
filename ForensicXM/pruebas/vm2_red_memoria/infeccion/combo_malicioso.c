#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/*
 * Escenario VM2 (extra) - Combo RWX + autoborrado.
 * Módulo de ForensicXM probado: -m (rama CRÍTICA)
 *
 * Este binario combina las dos técnicas que individualmente prueban
 * rwx_proc y malware_test, en un único proceso. Es el caso para el
 * que se diseñó la rama de severidad CRÍTICA en el módulo de memoria
 * tras la validación de la VM0:
 *
 *   1. Reserva una página de memoria con permisos RWX (igual que
 *      rwx_proc.c) - característica de inyección de shellcode.
 *   2. Se autoborra del disco (igual que self_delete.c) - característica
 *      de evasión post-explotación.
 *
 * Ningún software legítimo combina ambas conductas. La detección de
 * este proceso valida que la regla
 *
 *      if (tiene_rwx && binario_borrado) -> CRÍTICO
 *
 * efectivamente discrimina malware real de motores JIT.
 *
 * Compilar y ejecutar desde la carpeta del escenario VM2:
 *   gcc combo_malicioso.c -o combo_malicioso
 *   ./combo_malicioso &
 *
 * Después analizar con:
 *   sudo ./bin/forensicXM -m
 */

int main(int argc, char *argv[]) {
    (void)argc;  // no usado
    // 1. Reservar región RWX (como rwx_proc)
    size_t len = 4096;
    void *region = mmap(NULL, len,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(region, 0x90, len);

    printf("[combo_malicioso] PID %d\n", getpid());
    printf("[combo_malicioso] Región RWX creada en %p\n", region);

    // 2. Autoborrarse (como self_delete)
    // argv[0] suele ser el path relativo, lo construimos absoluto si hace falta
    if (unlink(argv[0]) == 0) {
        printf("[combo_malicioso] Me he borrado del disco (%s). Soy un fantasma.\n", argv[0]);
    } else {
        perror("[combo_malicioso] Error al autoborrarme");
        // No abortamos: la región RWX ya está, al menos eso prueba
    }

    printf("[combo_malicioso] Durmiendo 10 minutos para ser analizado...\n");
    printf("[combo_malicioso] Ahora ejecuta:  sudo ./bin/forensicXM -m\n");

    sleep(600);

    munmap(region, len);
    return 0;
}
