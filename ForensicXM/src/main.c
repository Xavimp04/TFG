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
        {"logs", no_argument, 0, 'l'},
        {"bin", no_argument, 0, 'b'},
        {"integrity", required_argument, 0, 'i'},
        {"report", required_argument, 0, 'r'},
        {0, 0, 0, 0}
    };
    
    // Si no hay argumentos, mostramos ayuda
    if (argc < 2) {
        printf("ForensicXM - Uso: %s [-v] [-u] [-p] [-l] [-b] [-i <ruta>] [-r <nombre>]\n", argv[0]);        
        return 1;
    }

    while ((opt = getopt_long(argc, argv, "vuplbi:r:", long_options, &option_index)) != -1) {
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
            case 'l':
                analizar_logs();
                break;
            case 'b':
                analizar_logins_binarios();
                break;
            case 'i':
                if (optarg) {
                    verificar_integridad(optarg);
                } else {
                    printf("Debe especificar una ruta con -i <ruta>\n");
                }
                break;
            case 'r':
                if (optarg) {
                    generar_reporte_completo(optarg);
                } else {
                    printf("Debe especificar un nombre de archivo con -r <nombre>\n");
                }
                break;
                
            default:
                printf("Opción no válida.\n");
        }
    }
    return 0;


}
