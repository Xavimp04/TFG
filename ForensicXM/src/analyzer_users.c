#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> // Para checkear privilegios
#include "forensics.h"

void determinar_seguridad_hash(char *hash) {
    if (hash[0] == '!') printf(" [Cuenta Bloqueada]");
    else if (hash[0] == '*') printf(" [Sin Password]");
    else if (strncmp(hash, "$y$", 3) == 0) printf(" (Hash: " GREEN "Yescrypt - Alta" RESET ")");
    else if (strncmp(hash, "$6$", 3) == 0) printf(" (Hash: " GREEN "SHA-512 - Alta" RESET ")");
    else if (strncmp(hash, "$1$", 3) == 0) printf(" (Hash: " RED "MD5 - DEBIL" RESET ")");
    else printf(" (Hash: Desconocido)");
}

void analizar_usuarios() {
    FILE *fp_pass, *fp_shad;
    char linea[512], linea_shad[1024];
    char usuario[64], pass_field[1024];
    int uid;

    printf("\n--- [" GREEN "Análisis Forense de Usuarios" RESET "] ---\n");

    if (geteuid() != 0) {
        printf(RED "[!] Advertencia: Ejecuta con SUDO para analizar contraseñas (/etc/shadow)" RESET "\n");
    }

    fp_pass = fopen("/etc/passwd", "r");
    if (!fp_pass) return;

    printf("%-15s %-5s %-20s\n", "Usuario", "UID", "Info Seguridad");
    printf("------------------------------------------------------------\n");

    while (fgets(linea, sizeof(linea), fp_pass)) {
        if (sscanf(linea, "%[^:]:%*[^:]:%d", usuario, &uid) == 2) {
            printf("%-15s %-5d", usuario, uid);

            // Intentamos buscar su hash en /etc/shadow (Tema 4)
            fp_shad = fopen("/etc/shadow", "r");
            if (fp_shad) {
                int encontrado = 0;
                while (fgets(linea_shad, sizeof(linea_shad), fp_shad)) {
                    char user_shad[64], hash_shad[1024];
                    if (sscanf(linea_shad, "%[^:]:%[^:]", user_shad, hash_shad) == 2) {
                        if (strcmp(usuario, user_shad) == 0) {
                            determinar_seguridad_hash(hash_shad);
                            encontrado = 1;
                            break;
                        }
                    }
                }
                fclose(fp_shad);
                if (!encontrado) printf(" [No en /etc/shadow]");
            }
            printf("\n");
        }
    }
    fclose(fp_pass);
}