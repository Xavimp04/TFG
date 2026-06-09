#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

/*
 * Escenario VM2 - Región de memoria RWX (Read+Write+Execute).
 * Módulo de ForensicXM probado: -m (memoria)
 * Las regiones RWX son un indicador clásico de inyección de
 * shellcode: un atacante necesita escribir código y luego
 * ejecutarlo en la misma página. El software legítimo casi
 * nunca lo hace (W^X). check_rwx_memory() debe detectar esto
 * leyendo /proc/[pid]/maps.
 *
 * Compilar:  gcc rwx_proc.c -o rwx_proc
 * Ejecutar:  ./rwx_proc &
 */

int main(void) {
    /* Reservamos una página con permisos R+W+X simultáneos */
    size_t len = 4096;
    void *region = mmap(NULL, len,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    /* Escribimos algo inocuo en la región (no es shellcode real) */
    memset(region, 0x90, len);  /* 0x90 = NOP, solo de relleno */

    printf("[rwx_proc] Región RWX creada en %p (PID %d)\n", region, getpid());
    printf("[rwx_proc] Dejar corriendo y lanzar: sudo ./bin/forensicXM -m\n");

    /* Mantener vivo el proceso para que sea analizable */
    sleep(600);

    munmap(region, len);
    return 0;
}
