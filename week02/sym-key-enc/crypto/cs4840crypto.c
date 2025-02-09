#include <openssl/evp.h>
#include <string.h>

/***************************************************
 * FILE *in: input file pointer
 * FILE *out: output file pointer
 * do_encrypt: 1 for encrption, 0 for decryption
 **************************************************/
int do_crypt(char* inFileName, char* outFileName, int do_encrypt)
{

    FILE* in;
    FILE* out;

    // open file
    in = fopen(inFileName, "r");
    out = fopen(outFileName, "w");

    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX* ctx;
    /* Bogus key and IV: we'd normally set these from
     * another source.
     */
    unsigned char key[] = "0123456789abcdeF";
    unsigned char iv[] = "1234567887654321";

    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
        do_encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    /* Now we can set key and IV */
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    for (;;) {
        inlen = fread(inbuf, 1, 1024, in);
        if (inlen <= 0)
            break;
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            /* Error */
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);

    // close files
    fclose(in);
    fclose(out);

    return 1;
}

int main(int argc, char* argv[])
{

    FILE* infp;
    FILE* outfp;

    // check input parameters
    if (argc != 4) {
        printf("usage: %s <input_file> <output_file> [enc|dec]\n", argv[0]);
        return 0;
    }

    // check paramters
    printf("input   = %s\n", argv[1]);
    printf("output  = %s\n", argv[2]);
    printf("enc/dec = %s\n", argv[3]);

    if (strcmp(argv[3], "enc") == 0) {
        do_crypt(argv[1], argv[2], 1);
        printf("encryption ... done\n");
    } else if (strcmp(argv[3], "dec") == 0) {
        do_crypt(argv[1], argv[2], 0);
        printf("decryption ... done\n");
    } else {
        printf("no operation..\n");
    }

    return 0;
}
