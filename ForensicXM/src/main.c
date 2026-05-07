#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include "forensics.h"
#include <string.h>
#include <limits.h>


int main(int argc, char *argv[]) {
    int opt;
    int option_index = 0;
    ForensicContext ctx;
    memset(&ctx, 0, sizeof(ForensicContext));

    static struct option long_options[] = {
        {"version", no_argument, 0, 'v'},
        {"users",   no_argument, 0, 'u'},
        {"persist", no_argument, 0, 'p'},
        {"logs", no_argument, 0, 'l'},
        {"bin", no_argument, 0, 'b'},
        {"net", no_argument, 0, 'n'},
        {"mem", no_argument, 0, 'm'},
        {"mem", no_argument, 0, 'm'},
        {"caps", no_argument, 0, 'c'},
        {"root", no_argument, 0, 'k'},
        {"json", no_argument, 0, 'j'},
        {"deadbox", required_argument, 0, 'd'},
        {"integrity", required_argument, 0, 'i'},
        {"report", required_argument, 0, 'r'},
        {0, 0, 0, 0}
    };
    
    // Si no hay argumentos, mostramos ayuda
    if (argc < 2) {
        printf("ForensicXM - Uso: %s [-v] [-u] [-p] [-l] [-b] [-n] [-m] [-c] [-k] [-j] [-d <ruta>] [-i <ruta>] [-r <nombre>]\n", argv[0]);        
        return 1;
    }

    while ((opt = getopt_long(argc, argv, "vuplbnmckjd:i:r:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v':
                printf("ForensicXM v0.1\n");
                identificar_sistema(&ctx);  // Mostramos la distro al pedir la versión
                break;
            case 'u':
                analizar_usuarios(&ctx);
                break;
            case 'p':
                analizar_persistencia(&ctx);
                break;
            case 'l':
                analizar_logs(&ctx);
                break;
            case 'b':
                analizar_logins_binarios(&ctx);
                break;
            case 'n':
                if (ctx.modo_deadbox) printf(YELLOW "[!] Modulo saltado: Análisis de Red no disponible en Deadbox.\n" RESET);
                else analizar_red(&ctx);
                break;
            case 'm':
                if (ctx.modo_deadbox) printf(YELLOW "[!] Modulo saltado: Análisis de Memoria no disponible en Deadbox.\n" RESET);
                else analizar_memoria(&ctx);
                break;
            case 'c':
                if (ctx.modo_deadbox) printf(YELLOW "[!] Modulo saltado: Análisis de Capacidades no disponible en Deadbox.\n" RESET);
                else analizar_capacidades(&ctx);
                break;
            case 'k':
                if (ctx.modo_deadbox) {
                    if (!ctx.modo_json) printf(YELLOW "[!] Modulo saltado: Análisis de Rootkits no disponible en Deadbox.\n" RESET);
                } else analizar_rootkits(&ctx);
                break;
            case 'j':
                ctx.modo_json = 1;
                ctx.json_report = cJSON_CreateObject();
                cJSON_AddStringToObject(ctx.json_report, "tool", "ForensicXM");
                break;
            case 'd':
                if (optarg) {
                    ctx.modo_deadbox = 1;
                    strncpy(ctx.root_dir, optarg, sizeof(ctx.root_dir) - 1);
                    // Eliminar barra final si la hay para evitar dobles barras
                    int len = strlen(ctx.root_dir);
                    if (len > 0 && ctx.root_dir[len-1] == '/') {
                        ctx.root_dir[len-1] = '\0';
                    }
                    printf(GREEN "[+] Modo Deadbox Activado. Raíz: %s\n" RESET, ctx.root_dir);
                }
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
                    generar_reporte_completo(optarg, &ctx);
                } else {
                    printf("Debe especificar un nombre de archivo con -r <nombre>\n");
                }
                break;
                
            default:
                printf("Opción no válida.\n");
        }
    }

    // Al finalizar, si estamos en modo JSON, imprimimos el objeto maestro
    if (ctx.modo_json && ctx.json_report) {
        char *json_string = cJSON_Print(ctx.json_report);
        printf("%s\n", json_string);
        free(json_string);
        cJSON_Delete(ctx.json_report);
    }

    return 0;

}
