#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdint.h>
#include <string>

/* AES key for Encryption and Decryption */
const static unsigned char aes_key[]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

/* Print Encrypted and Decrypted data packets */
void print_data(const char *tittle, const void* data, int len);

bool LLVMFuzzerAES(const uint8_t *Data, size_t Size) {

    /* Input data to encrypt */
    unsigned char aes_input[]={0x0,0x1,0x2,0x3,0x4,0x5};

    std::string s(reinterpret_cast<const char *>(Data), Size);


    /* Init vector */
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, AES_BLOCK_SIZE);

    /* Buffers for Encryption and Decryption */
    unsigned char enc_out[Size];
    unsigned char dec_out[Size];

    /* AES-128 bit CBC Encryption */
    AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);
    AES_cbc_encrypt(Data, enc_out, Size, &enc_key, iv, AES_ENCRYPT);

    /* AES-128 bit CBC Decryption */
    memset(iv, 0x00, AES_BLOCK_SIZE); // don't forget to set iv vector again, else you can't decrypt data properly
    AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits
    AES_cbc_encrypt(enc_out, dec_out, Size, &dec_key, iv, AES_DECRYPT);

    /* Printing and Verifying */
    print_data("\n Original %s ",s.c_str(), Size); // you can not print data as a string, because after Encryption its not ASCII

    print_data("\n Encrypted",enc_out, sizeof(enc_out));

    print_data("\n Decrypted",dec_out, sizeof(dec_out));

    return 0;
}

void print_data(const char *tittle, const void* data, int len)
{
    printf("%s : ",tittle);
    const unsigned char * p = (const unsigned char*)data;
    int i = 0;

    for (; i<len; ++i)
        printf("%02X ", *p++);

    printf("\n");
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    LLVMFuzzerAES(Data,Size);
    return 0;
}
