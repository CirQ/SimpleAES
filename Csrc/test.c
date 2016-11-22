#include<stdio.h>
#include<memory.h>
#include"AES.c"


int main(){

    /*
     * first we need to define the secret key and the plaintext
     * 
     * then give the space of the ciphertext (as input parameter)
     */
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    //debug(key);
    unsigned char plaintext[BLOCKSIZE * N] = {
        0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
        0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34
    };
    unsigned char ciphertext[BLOCKSIZE * N] = {0};


    /*
     * show the secret key and the plaintext (for debug)
     */
    printf("\nThe secret key is:\n");
    for(int i = 0; i < 16; i++)
        printf("%02X", key[i]);
    printf("\n\n");

    printf("\nThe plain-text is:\n");
    for(int i = 0; i < 16; i++)
        printf("%02X", plaintext[i]);
    printf("\n\n");


    /*
     * then encrpyt the plaintext, show the key schedule
     */
    Encrypt(key, plaintext, ciphertext);
    
    printf("\nThe key schedule is:\n");
    ShowKeySchedule();


    /*
     * show the ciphertext, then decypt it
     */
    printf("\nThe cipher-text is:\n");
    for(int i = 0; i < 16; i++)
        printf("%02X", ciphertext[i]);
    printf("\n\n");


    /*
     * reset the memory of the plain text, then decrypt the cipher
     */
    memset(plaintext, 0, BLOCKSIZE*N);
    Decrypt(key, ciphertext, plaintext);
    
    printf("\nThe decrypted plain-text is:\n");
    for(int i = 0; i < 16; i++)
        printf("%02X", plaintext[i]);
    printf("\n\n");

    return 0;
}
