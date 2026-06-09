#include <stdio.h>
#include <unistd.h>

/*
 * Escenario VM3 - Proceso no-root con Linux Capabilities críticas.
 * Módulo de ForensicXM probado: -c (capabilities)
 *
 * Este binario no hace nada peligroso: solo duerme. El "ataque"
 * se simula asignándole capabilities con setcap (ver infectar_vm3.sh).
 * Representa la técnica post-explotación de "secuestrar" una
 * capability concreta (cap_sys_ptrace para inyectar en procesos,
 * cap_net_raw para sniffing) sin necesidad de ser root.
 *
 * Compilar:  gcc cap_holder.c -o cap_holder
 * El script de infección le aplica:
 *   setcap cap_sys_ptrace,cap_net_raw+ep cap_holder
 * Ejecutar como usuario NORMAL (no root):  ./cap_holder &
 */

int main(void) {
    printf("[cap_holder] Proceso vivo (PID %d, UID %d)\n",
           getpid(), getuid());
    printf("[cap_holder] Dejar corriendo y lanzar: sudo ./bin/forensicXM -c\n");
    sleep(600);
    return 0;
}
