#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include "forensics.h"


// Función auxiliar para convertir IP hexadecimal a string (Little Endian)
void hex_to_ip(char *hex, char *buffer) {
    unsigned int ip;
    sscanf(hex, "%X", &ip);
    struct in_addr addr;
    addr.s_addr = ip;
    strcpy(buffer, inet_ntoa(addr));
}

// Función auxiliar para convertir Puerto hexadecimal a entero
int hex_to_port(char *hex) {
    unsigned int port;
    sscanf(hex, "%X", &port);
    return port;
}

// Estructura para almacenar el mapeo de Inode -> PID y Nombre
typedef struct {
    unsigned long inode;
    char pid[16];
    char name[64];
} SocketProcessMap;

SocketProcessMap *socket_map = NULL;
int socket_map_count = 0;
int socket_map_capacity = 0;

// Agrega un socket al mapa
void add_socket_map(unsigned long inode, const char* pid, const char* name) {
    if (socket_map_count >= socket_map_capacity) {
        socket_map_capacity = (socket_map_capacity == 0) ? 1024 : socket_map_capacity * 2;
        socket_map = realloc(socket_map, socket_map_capacity * sizeof(SocketProcessMap));
    }
    socket_map[socket_map_count].inode = inode;
    strncpy(socket_map[socket_map_count].pid, pid, 15);
    socket_map[socket_map_count].pid[15] = '\0';
    strncpy(socket_map[socket_map_count].name, name, 63);
    socket_map[socket_map_count].name[63] = '\0';
    socket_map_count++;
}

// Recorre /proc una sola vez y almacena todos los inodes de sockets
void preload_process_sockets() {
    DIR *dir;
    struct dirent *entry;
    
    dir = opendir("/proc");
    if (!dir) return;

    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;

        char path_fd[512];
        snprintf(path_fd, sizeof(path_fd), "/proc/%s/fd", entry->d_name);

        DIR *dir_fd = opendir(path_fd);
        if (!dir_fd) continue;

        char name_buf[64] = "-";
        int name_loaded = 0;

        struct dirent *entry_fd;
        while ((entry_fd = readdir(dir_fd)) != NULL) {
            if (entry_fd->d_type == DT_LNK) {
                char link_target[PATH_MAX];
                char path_link[PATH_MAX];
                snprintf(path_link, sizeof(path_link), "%s/%s", path_fd, entry_fd->d_name);

                ssize_t len = readlink(path_link, link_target, sizeof(link_target) - 1);
                if (len != -1) {
                    link_target[len] = '\0';
                    if (strstr(link_target, "socket:")) {
                        unsigned long inode_found;
                        if (sscanf(link_target, "socket:[%lu]", &inode_found) == 1) {
                            if (!name_loaded) {
                                char path_comm[PATH_MAX];
                                snprintf(path_comm, sizeof(path_comm), "/proc/%s/comm", entry->d_name);
                                FILE *fp_comm = fopen(path_comm, "r");
                                if (fp_comm) {
                                    if(fgets(name_buf, sizeof(name_buf), fp_comm)) {
                                        name_buf[strcspn(name_buf, "\n")] = 0;
                                    }
                                    fclose(fp_comm);
                                }
                                name_loaded = 1;
                            }
                            add_socket_map(inode_found, entry->d_name, name_buf);
                        }
                    }
                }
            }
        }
        closedir(dir_fd);
    }
    closedir(dir);
}

// Búsqueda en el array precargado
void encontrar_info_proceso_opt(unsigned long inode, char *pid_buf, char *name_buf) {
    strcpy(pid_buf, "-");
    strcpy(name_buf, "-");
    for (int i = 0; i < socket_map_count; i++) {
        if (socket_map[i].inode == inode) {
            strcpy(pid_buf, socket_map[i].pid);
            strcpy(name_buf, socket_map[i].name);
            return;
        }
    }
}

// Limpia el mapa de memoria
void cleanup_socket_map() {
    if (socket_map) {
        free(socket_map);
        socket_map = NULL;
    }
    socket_map_count = 0;
    socket_map_capacity = 0;
}

void analizar_red() {
    FILE *fp;
    char linea[1024];
    char local_addr_hex[64], rem_addr_hex[64];
    char local_ip[16], rem_ip[16];
    char *local_port_hex, *rem_port_hex;
    unsigned int estado;
    unsigned long inode;
    
    // Estados TCP según include/net/tcp_states.h
    const char *estados_tcp[] = {
        "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
        "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING"
    };

    cJSON *net_array = NULL;
    if (modo_json) {
        net_array = cJSON_AddArrayToObject(json_report, "network_connections");
    } else {
        printf("\n--- [" GREEN "Análisis de Conexiones de Red (Sin netstat)" RESET "] ---\n");
        if (geteuid() != 0) {
            printf(YELLOW "[!] Nota: Ejecuta con SUDO para ver PIDs y Nombres de procesos.\n" RESET);
        }
        printf("%-22s %-22s %-12s %-10s %-8s %-15s\n", "Local Address", "Remote Address", "State", "Inode", "PID", "Program");
        printf("--------------------------------------------------------------------------------------------------\n");
    }

    // Precargamos la tabla de sockets para Optimización
    preload_process_sockets();

    // Abrimos /proc/net/tcp
    fp = fopen("/proc/net/tcp", "r");
    if (fp == NULL) {
        perror(RED "    [-] Error al abrir /proc/net/tcp" RESET);
        return;
    }

    // Saltamos la primera línea (cabecera)
    fgets(linea, sizeof(linea), fp);

    while (fgets(linea, sizeof(linea), fp)) {
        // Formato: sl  local_address rem_address   st ... inode
        // Ejemplo:  0: 0100007F:1F90 00000000:0000 0A ... 20601
        
        char dummy[64]; // Para saltar campos intermedios
        
        // Un parsing manual simple
        char *token = strtok(linea, " "); // sl
        token = strtok(NULL, " "); // local_address
        
        if (token) {
            strcpy(local_addr_hex, token);
            local_port_hex = strchr(local_addr_hex, ':');
            if (local_port_hex) {
                *local_port_hex = '\0'; // Separamos IP
                local_port_hex++;       // Apuntamos al puerto
            }

            token = strtok(NULL, " "); // rem_address
            if (token) {
                 strcpy(rem_addr_hex, token);
                 rem_port_hex = strchr(rem_addr_hex, ':');
                 if (rem_port_hex) {
                     *rem_port_hex = '\0';
                     rem_port_hex++;
                 }
                 
                 token = strtok(NULL, " "); // st
                 sscanf(token, "%X", &estado);

                 // Saltamos: tx_queue rx_queue tr tm->when retrnsmt uid timeout
                 for(int i=0; i<5; i++) strtok(NULL, " ");
                 
                 // Inode
                 token = strtok(NULL, " ");
                 if(token) sscanf(token, "%lu", &inode);

                 // Convertir y mostrar
                 hex_to_ip(local_addr_hex, local_ip);
                 hex_to_ip(rem_addr_hex, rem_ip);
                 
                 char local_str[32], rem_str[32];
                 snprintf(local_str, sizeof(local_str), "%s:%d", local_ip, hex_to_port(local_port_hex));
                 snprintf(rem_str, sizeof(rem_str), "%s:%d", rem_ip, hex_to_port(rem_port_hex));
                 
                 const char *estado_str = (estado < 12) ? estados_tcp[estado] : "UNKNOWN";
                 
                 // Buscar PID y Nombre en el mapa en memoria
                 char pid_str[16], name_str[64];
                 encontrar_info_proceso_opt(inode, pid_str, name_str);

                 if (modo_json && net_array) {
                     cJSON *conn_item = cJSON_CreateObject();
                     cJSON_AddStringToObject(conn_item, "protocol", "TCP");
                     cJSON_AddStringToObject(conn_item, "local_address", local_str);
                     cJSON_AddStringToObject(conn_item, "remote_address", rem_str);
                     cJSON_AddStringToObject(conn_item, "state", estado_str);
                     cJSON_AddNumberToObject(conn_item, "inode", inode);
                     if (strcmp(pid_str, "-") != 0) {
                         cJSON_AddNumberToObject(conn_item, "pid", atoi(pid_str));
                     }
                     if (strcmp(name_str, "-") != 0) {
                         cJSON_AddStringToObject(conn_item, "process_name", name_str);
                     }
                     cJSON_AddItemToArray(net_array, conn_item);
                 } else {
                     // Colorear conexiones ESTABLECIDAS o LISTEN
                     if (estado == 1) { // ESTABLISHED
                         printf(GREEN "%-22s %-22s %-12s %-10lu %-8s %-15s" RESET "\n", local_str, rem_str, estado_str, inode, pid_str, name_str);
                     } else if (estado == 10) { // LISTEN
                         printf("%-22s %-22s %-12s %-10lu %-8s %-15s\n", local_str, rem_str, estado_str, inode, pid_str, name_str);
                     } else {
                         printf("%-22s %-22s %-12s %-10lu %-8s %-15s\n", local_str, rem_str, estado_str, inode, pid_str, name_str);
                     }
                 }
            }
        }
    }

    fclose(fp);
    cleanup_socket_map();
    if (!modo_json) {
        printf("--------------------------------------------------------------------------------------------------\n");
    }
}
