/**
 * @file forensics.h
 * @brief Cabecera principal del framework de análisis forense ForensicXM.
 * 
 * Este archivo contiene las declaraciones de las funciones de análisis, 
 * así como los macros del sistema de logging centralizado y paleta de colores.
 */

#ifndef FORENSICS_H
#define FORENSICS_H

#include "cJSON.h"

#include <limits.h>

/**
 * @brief Estructura de Contexto que encapsula el estado global de ejecución.
 */
typedef struct {
    char root_dir[1024];
    int modo_deadbox;
    int modo_json;
    cJSON *json_report;
} ForensicContext;

#include <stdio.h>

/** @name Paleta de Colores
 *  Constantes para dar formato a la salida por consola.
 */
///@{
#define RED "\x1B[31m"
#define GREEN "\x1B[32m"
#define YELLOW "\x1B[33m"
#define BLUE "\x1B[34m"
#define MAGENTA "\x1B[35m"
#define CYAN "\x1B[36m"
#define RESET "\x1B[0m"
///@}

/** @name Sistema de Logs Centralizado
 *  Macros para estandarizar la salida por pantalla, evitando el uso directo de printf.
 */
///@{
#define LOG_INFO(fmt, ...) printf(GREEN "[+] " RESET fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) printf(YELLOW "[!] " RESET fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf(RED "[-] " RESET fmt "\n", ##__VA_ARGS__)
#define LOG_TITLE(fmt, ...) printf("\n--- [" GREEN fmt RESET "] ---\n", ##__VA_ARGS__)
///@}

/**
 * @brief Identifica la distribución y la versión del kernel del sistema.
 * @param root_dir Directorio raíz del sistema a analizar (puede ser '/' o un entorno montado).
 */
void identificar_sistema(ForensicContext *ctx);

/**
 * @brief Analiza los usuarios del sistema buscando contraseñas débiles o sin contraseña.
 * @param root_dir Directorio raíz del sistema a analizar.
 */
void analizar_usuarios(ForensicContext *ctx);

/**
 * @brief Busca mecanismos de persistencia como Cron jobs y Systemd units.
 * @param root_dir Directorio raíz del sistema a analizar.
 */
void analizar_persistencia(ForensicContext *ctx);

/**
 * @brief Analiza los logs de autenticación (auth.log / secure) buscando accesos no autorizados.
 * @param root_dir Directorio raíz del sistema a analizar.
 */
void analizar_logs(ForensicContext *ctx); 

/**
 * @brief Analiza el historial de logins binarios (wtmp).
 * @param root_dir Directorio raíz del sistema a analizar.
 */
void analizar_logins_binarios(ForensicContext *ctx); 

/**
 * @brief Analiza las conexiones de red en busca de anomalías.
 * @param root_dir Directorio raíz del sistema a analizar.
 */
void analizar_red(ForensicContext *ctx); 

/**
 * @brief Analiza la memoria RAM en busca de procesos ocultos o sospechosos.
 * @param root_dir Directorio raíz del sistema a analizar.
 */
void analizar_memoria(ForensicContext *ctx); 

/**
 * @brief Busca indicios de Loadable Kernel Modules (LKM) ocultos comparando proc y sysfs.
 * @param root_dir Directorio raíz del sistema a analizar.
 */
void analizar_rootkits(ForensicContext *ctx);

/**
 * @brief Analiza las capabilities binarias asignadas a los ejecutables del sistema.
 * @param root_dir Directorio raíz del sistema a analizar.
 */
void analizar_capacidades(ForensicContext *ctx);

/**
 * @brief Verifica la integridad de un archivo o directorio calculando su hash.
 * @param ruta Ruta del archivo o directorio a verificar.
 */
void verificar_integridad(const char *ruta); 

/**
 * @brief Genera un reporte completo en el archivo especificado.
 * @param nombre_archivo Nombre del archivo donde se guardará el reporte.
 * @param root_dir Directorio raíz del sistema a analizar.
 */
void generar_reporte_completo(const char *nombre_archivo, ForensicContext *ctx); 

/**
 * @brief Calcula y muestra por pantalla el hash SHA-256 de un archivo.
 * @param ruta Ruta del archivo.
 */
void calcular_sha256_archivo(const char *ruta); 

/* Variables de estado y configuración global */




#endif