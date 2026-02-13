#ifndef FORENSICS_H
#define FORENSICS_H

#define RED "\x1B[31m"
#define GREEN "\x1B[32m"
#define YELLOW "\x1B[33m"
#define BLUE "\x1B[34m"
#define MAGENTA "\x1B[35m"
#define CYAN "\x1B[36m"
#define RESET "\x1B[0m"

void identificar_sistema();
void analizar_usuarios();
void analizar_persistencia();
void analizar_logs(); 
void analizar_logins_binarios(); 
void verificar_integridad(const char *ruta); 



void generar_reporte_completo(const char *nombre_archivo); 



#endif