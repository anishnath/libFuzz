#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>

bool LLVMFuzzerSHA(const uint8_t *Data, size_t Size) {

 EVP_MD_CTX *mdctx;
 const EVP_MD *md;
 unsigned char md_value[EVP_MAX_MD_SIZE];
 unsigned int md_len, i;
 std::string s(reinterpret_cast<const char *>(Data), Size);
// printf ("Data is %s\n", s.c_str());
 OpenSSL_add_all_digests();
 md = EVP_get_digestbyname("SHA");


 mdctx = EVP_MD_CTX_create();
 EVP_DigestInit_ex(mdctx, md, NULL);
 EVP_DigestUpdate(mdctx, s.c_str(), Size);
 EVP_DigestUpdate(mdctx, s.c_str(), Size);
 EVP_DigestFinal_ex(mdctx, md_value, &md_len);
 EVP_MD_CTX_destroy(mdctx);

 printf("Digest is: ");
 for(i = 0; i < md_len; i++)
  printf("%02x", md_value[i]);
 printf("\n");
 return 0;
}

bool LLVMFuzzerrmd160(const uint8_t *Data, size_t Size) {

 EVP_MD_CTX *mdctx;
 const EVP_MD *md;
 unsigned char md_value[EVP_MAX_MD_SIZE];
 unsigned int md_len, i;
 std::string s(reinterpret_cast<const char *>(Data), Size);
// printf ("Data is %s\n", s.c_str());
 OpenSSL_add_all_digests();
 md = EVP_get_digestbyname("rmd160");


 mdctx = EVP_MD_CTX_create();
 EVP_DigestInit_ex(mdctx, md, NULL);
 EVP_DigestUpdate(mdctx, s.c_str(), Size);
 EVP_DigestUpdate(mdctx, s.c_str(), Size);
 EVP_DigestFinal_ex(mdctx, md_value, &md_len);
 EVP_MD_CTX_destroy(mdctx);

 printf("Digest is: ");
 for(i = 0; i < md_len; i++)
  printf("%02x", md_value[i]);
 printf("\n");
 return 0;
}

bool LLVMFuzzerMD4(const uint8_t *Data, size_t Size) {

 EVP_MD_CTX *mdctx;
 const EVP_MD *md;
 unsigned char md_value[EVP_MAX_MD_SIZE];
 unsigned int md_len, i;
 std::string s(reinterpret_cast<const char *>(Data), Size);
// printf ("Data is %s\n", s.c_str());
 OpenSSL_add_all_digests();
 md = EVP_get_digestbyname("MD4");


 mdctx = EVP_MD_CTX_create();
 EVP_DigestInit_ex(mdctx, md, NULL);
 EVP_DigestUpdate(mdctx, s.c_str(), Size);
 EVP_DigestUpdate(mdctx, s.c_str(), Size);
 EVP_DigestFinal_ex(mdctx, md_value, &md_len);
 EVP_MD_CTX_destroy(mdctx);

 printf("Digest is: ");
 for(i = 0; i < md_len; i++)
  printf("%02x", md_value[i]);
 printf("\n");
 return 0; 
}


bool LLVMFuzzerSHA1(const uint8_t *Data, size_t Size) {

 EVP_MD_CTX *mdctx;
 const EVP_MD *md;
 unsigned char md_value[EVP_MAX_MD_SIZE];
 unsigned int md_len, i;
 std::string s(reinterpret_cast<const char *>(Data), Size);
// printf ("Data is %s\n", s.c_str());
 OpenSSL_add_all_digests();
 md = EVP_get_digestbyname("SHA1");


 mdctx = EVP_MD_CTX_create();
 EVP_DigestInit_ex(mdctx, md, NULL);
 EVP_DigestUpdate(mdctx, s.c_str(), Size);
 EVP_DigestUpdate(mdctx, s.c_str(), Size);
 EVP_DigestFinal_ex(mdctx, md_value, &md_len); 
 EVP_MD_CTX_destroy(mdctx);

 printf("Digest is: ");
 for(i = 0; i < md_len; i++)
  printf("%02x", md_value[i]);
 printf("\n");

 /* Call this once before exit. */
 EVP_cleanup();

 return 0;


}

bool LLVMFuzzerMD5(const uint8_t *Data, size_t Size) {

 EVP_MD_CTX *mdctx;
 const EVP_MD *md;
 unsigned char md_value[EVP_MAX_MD_SIZE];
 unsigned int md_len, i;
 std::string s(reinterpret_cast<const char *>(Data), Size);
// printf ("Data is %s\n", s.c_str());
 OpenSSL_add_all_digests();
 md = EVP_get_digestbyname("MD5");


 mdctx = EVP_MD_CTX_create();
 EVP_DigestInit_ex(mdctx, md, NULL);
 EVP_DigestUpdate(mdctx, s.c_str(), Size);
 EVP_DigestUpdate(mdctx, s.c_str(), Size);
 EVP_DigestFinal_ex(mdctx, md_value, &md_len);
 EVP_MD_CTX_destroy(mdctx);

 printf("Digest is: ");
 for(i = 0; i < md_len; i++)
  printf("%02x", md_value[i]);
 printf("\n");

 /* Call this once before exit. */
 EVP_cleanup();

 return 0;

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

 LLVMFuzzerSHA1(Data,Size);
 LLVMFuzzerSHA(Data,Size);
 LLVMFuzzerMD5 (Data,Size);
 LLVMFuzzerMD4 (Data,Size); 
 LLVMFuzzerrmd160 (Data,Size);
 return 0;
}
