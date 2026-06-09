#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/*
 * Escenario VM2 - Listener sospechoso en puerto alto.
 * Módulo de ForensicXM probado: -n (red)
 * Simula el lado servidor de una backdoor: abre un puerto en LISTEN
 * y se queda esperando. NO ejecuta comandos remotos: solo mantiene
 * el socket abierto para que el análisis de red lo mapee (Inode->PID).
 *
 * Compilar:  gcc fake_backdoor.c -o fake_backdoor
 * Ejecutar:  ./fake_backdoor &
 */

#define PUERTO 4444   /* puerto clásico de Metasploit, fácil de justificar */

int main(void) {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PUERTO);

    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(srv, 1) < 0) { perror("listen"); return 1; }

    printf("[fake_backdoor] Escuchando en 0.0.0.0:%d (PID %d)\n", PUERTO, getpid());
    printf("[fake_backdoor] Dejar corriendo y lanzar: sudo ./bin/forensicXM -n\n");

    /* Mantener el proceso vivo con el puerto en LISTEN */
    for (;;) pause();
    return 0;
}
