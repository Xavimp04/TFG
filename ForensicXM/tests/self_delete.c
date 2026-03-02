#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    printf("Soy un proceso malicioso (PID: %d)\n", getpid());
    
    // Me borro a mí mismo
    if (unlink("tests/malware_test") == 0) {
        printf("Me he borrado del disco. Ahora soy un fantasma.\n");
    } else {
        perror("Error al borrarme");
    }

    // Mantengo el proceso vivo para que ForensicXM me detecte
    printf("Durmiendo para ser analizado...\n");
    sleep(60); 
    
    return 0;
}
