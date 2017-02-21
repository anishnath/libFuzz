#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "fuzzer.h"

static int FuzzerInitialize()
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_get_state();
    CRYPTO_free_ex_index(0, -1);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    
    const unsigned char *p = buf;
    unsigned char *der = NULL;

    X509_CRL *crl = d2i_X509_CRL(NULL, &p, len);
    if (crl != NULL) {
        BIO *bio = BIO_new(BIO_s_null());
        X509_CRL_print(bio, crl);
        BIO_free(bio);

        i2d_X509_CRL(crl, &der);
        OPENSSL_free(der);
        OPENSSL_free(der);

        X509_CRL_free(crl);
    }
    ERR_clear_error();

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzerInitialize();   
    FuzzerTestOneInput(Data,Size);
    return 0;
}
