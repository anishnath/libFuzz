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

#define MAX_VECTOR_SIZE 64

bool LLVMFuzzerAES_ige(const uint8_t *Data, size_t Size) {

        if (Size <  8) {
            return 0;
       }
  	
      
        unsigned char ckey[] =  "MIICXQIBAAKBgQCJMfzpf1Y3RHwMRfIFLCbWsCXaofCL11gi16Nfp1RBpGBZbnCGMIICXQIBAAKBgQCJMfzpf1Y3RHwMRfIFLCbWsCXaofCL11gi16Nfp1RBpGBZbnC1";
	unsigned char ivec[] = "01234567890123456";
	int bytes_read;
	unsigned char indata[MAX_VECTOR_SIZE];
	unsigned char outdata[Size];
	unsigned char decryptdata[Size];
	/* data structure that contains the key itself */
	AES_KEY keyEn;
	/* set the encryption key */
	AES_set_encrypt_key(Data, 128, &keyEn);
	/* set where on the 128 bit encrypted block to begin encryption*/
	int num = 0;
	bytes_read = sizeof(indata);

        //AES_ige_encrypt
        AES_ige_encrypt (Data, outdata, bytes_read, &keyEn, ivec, AES_ENCRYPT);
        AES_ige_encrypt (Data, outdata, bytes_read, &keyEn, ivec, AES_DECRYPT);
       
      
        return 0;

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    LLVMFuzzerAES_ige(Data,Size);
    return 0;
}
