#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include "forensics.h"

/**
 * @brief Analiza el formato de un hash de contraseña y determina su nivel de seguridad.
 * @param hash Cadena de texto con el hash extraído de /etc/shadow.
 */
static void determinar_seguridad_hash(char *hash) {
    if (hash[0] == '!') printf(" [Cuenta Bloqueada]");
    else if (hash[0] == '*') printf(" [Sin Password]");
    else if (strncmp(hash, "$y$", 3) == 0) printf(" (Hash: " GREEN "Yescrypt - Alta" RESET ")");
    else if (strncmp(hash, "$6$", 3) == 0) printf(" (Hash: " GREEN "SHA-512 - Alta" RESET ")");
    else if (strncmp(hash, "$1$", 3) == 0) printf(" (Hash: " RED "MD5 - DEBIL" RESET ")");
    else printf(" (Hash: Desconocido)");
}

void analizar_usuarios(ForensicContext *ctx) {
    FILE *fp_pass, *fp_shad;
    char linea[512], linea_shad[1024];
    char usuario[64];
    int uid;

    printf("\n--- [" GREEN "Análisis Forense de Usuarios" RESET "] ---\n");

    if (geteuid() != 0) {
        printf(RED "[!] Advertencia: Ejecuta con SUDO para analizar contraseñas (/etc/shadow)" RESET "\n");
    }

    char path_pass[PATH_MAX];
    snprintf(path_pass, sizeof(path_pass), "%s/etc/passwd", ctx->root_dir);

    fp_pass = fopen(path_pass, "r");
    if (!fp_pass) return;

    printf("%-15s %-5s %-20s\n", "Usuario", "UID", "Info Seguridad");
    printf("------------------------------------------------------------\n");

    while (fgets(linea, sizeof(linea), fp_pass)) {
        if (sscanf(linea, "%[^:]:%*[^:]:%d", usuario, &uid) == 2) {
            printf("%-15s %-5d", usuario, uid);

            char path_shad[PATH_MAX];
            snprintf(path_shad, sizeof(path_shad), "%s/etc/shadow", ctx->root_dir);
            fp_shad = fopen(path_shad, "r");
            if (fp_shad) {
                int encontrado = 0;
                while (fgets(linea_shad, sizeof(linea_shad), fp_shad)) {
                    // CORRECCIÓN (validación VM1): el parser original usaba
                    //   sscanf(linea, "%[^:]:%[^:]", user, hash)
                    // que devuelve 1 (no 2) cuando el campo de hash está vacío,
                    // descartando la línea. Esto provocaba que cuentas SIN
                    // contraseña ('usuario::...') se reportaran como "no en
                    // /etc/shadow" en vez de marcarse como amenaza.
                    //
                    // Ahora extraemos el nombre de usuario y el hash a mano,
                    // distinguiendo explícitamente el caso de hash vacío.
                    char *primer_colon  = strchr(linea_shad, ':');
                    if (!primer_colon) continue;
                    char *segundo_colon = strchr(primer_colon + 1, ':');
                    if (!segundo_colon) continue;

                    // Extraemos el nombre del usuario (hasta el primer ':')
                    char user_shad[64];
                    size_t user_len = primer_colon - linea_shad;
                    if (user_len >= sizeof(user_shad)) continue;
                    strncpy(user_shad, linea_shad, user_len);
                    user_shad[user_len] = '\0';

                    if (strcmp(usuario, user_shad) != 0) continue;

                    // El campo de hash va del primer al segundo ':'
                    size_t hash_len = segundo_colon - (primer_colon + 1);
                    if (hash_len == 0) {
                        // Hash VACÍO: cuenta sin contraseña, autenticación
                        // sin password requerida. Indicador de compromiso.
                        printf(" [" RED "Sin Password (campo vacío)" RESET "]");
                    } else {
                        char hash_shad[1024];
                        if (hash_len >= sizeof(hash_shad)) hash_len = sizeof(hash_shad) - 1;
                        strncpy(hash_shad, primer_colon + 1, hash_len);
                        hash_shad[hash_len] = '\0';
                        determinar_seguridad_hash(hash_shad);
                    }
                    encontrado = 1;
                    break;
                }
                fclose(fp_shad);
                if (!encontrado) printf(" [No en /etc/shadow]");
            }
            printf("\n");
        }
    }
    fclose(fp_pass);
}
