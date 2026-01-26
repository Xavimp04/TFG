#include <stdio.h>
#include <getopt.h>
#include "forensics.h"

int main(int argc, char *argv[]) {
    int opt;
    int option_index = 0;

    static struct option long_options[] = {
        {"version", no_argument, 0, 'v'},
        {"users",   no_argument, 0, 'u'},
        {"persist", no_argument, 0, 'p'},
        {0, 0, 0, 0}
    };
    
    // Si no hay argumentos, mostramos ayuda
    if (argc < 2) {
        printf("ForensicXM - Uso: %s [-v] [-u] [-p]\n", argv[0]);        
        return 1;
    }

    while ((opt = getopt_long(argc, argv, "vup", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v':
                printf("ForensicXM v0.1\n");
                identificar_sistema();  // Mostramos la distro al pedir la versión
                break;
            case 'u':
                analizar_usuarios();
                break;
            case 'p':
                analizar_persistencia();
                break;
            default:
                printf("Opción no válida.\n");
        }
    }
    return 0;


}
