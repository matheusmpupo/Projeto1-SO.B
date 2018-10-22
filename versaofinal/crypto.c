/*
    Ettore Biazon Baccan        - 16000465
    Mateus Henrique Zorzi       - 16100661
    Matheus Martins Pupo        - 16145559
    Rodrigo Okada Mendes        - 16056848
*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
 
#define BUFFER_LENGTH 256               ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM
 
int main( int argc, char *argv[] ) {
    int retorno, dispositivo, tamanho, i;
    char stringToSend[BUFFER_LENGTH];
    printf("Opening Crypto Device...\n");
    dispositivo = open("/dev/crypto", O_RDWR);             // Open the device with read/write access
    if (dispositivo < 0){
        perror("Failed to open device! Uninitialized Kernel Module!");
        return errno;
    }
    tamanho = 0 + argc - 2;  // Variável utilizada para copiar frases com espaço
    if (argc > 2 && (strcmp(argv[1], "c") == 0 || strcmp(argv[1], "d") == 0 || strcmp(argv[1], "h") == 0)) {
        strcpy(stringToSend, argv[1]);
        for (i = 0; i < tamanho; i++) {
            strcat(stringToSend, " ");
            strcat(stringToSend, argv[i + 2]);
        }
    }
    else {
        printf("No parameters detected: ./sudo teste 'operation' 'data'\n  Operation must be:\n    [c] Encrypt\n    [d] Decrypt\n    [h] Hash\n  Choose one next time!\nClosing user program...\n");
        return 0;
    }

    // printa qual mensagem será escrita no dispositivo
    printf("Writing [");
    i = 2;
    while (stringToSend[i] != '\0') {
        if (stringToSend[i] != '\0') {
            printf("%c", stringToSend[i]);
        }
        i++;
    }
    printf("] on device with operator [%c]\n", stringToSend[0]);
   
    retorno = write(dispositivo, stringToSend, strlen(stringToSend)); // Send the string to the LKM
    if (retorno < 0){
        perror("Failed to write on device!");
        return errno;
    } 
    printf("Press ENTER to continue!\n");
    getchar();
 
    printf("Reading from device...\n");
    retorno = read(dispositivo, receive, BUFFER_LENGTH);        // Read the response from the LKM
    if (retorno < 0){
        perror("Failed to reading from device");
        return errno;
    }
    if (*stringToSend == 'c'){
    printf("Message received: [");
    for (int k = 0; k < 16; k++){
        printf("%02hhx", (unsigned char) receive[k]);
    }
    printf("]\n");
    } else {
        printf("Message received: [%s]\n", receive);
printf("Message received2: [");
    for (int k = 0; k < 16; k++){
        printf("%02hhx", (unsigned char) receive[k]);
    }
    }
    return 0;
}
