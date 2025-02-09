#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(int argc, char *argv[]) {
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  int md_len, i;

  OpenSSL_add_all_digests();
  
  // parameter checking
  if(argc != 3) {
    printf("Usage: %s <hash algorithm> <message>\n", argv[0]);
    printf(" e.g.: %s md5 \"hello danny\"\n", argv[0]);
    exit(1);
  }
  
  // show input values
  printf("hash algorithm = %s\n", argv[1]);
  printf("message = %s\n", argv[2]);
   
  md = EVP_get_digestbyname(argv[1]);
  if(!md) {
         printf("Unknown message digest (hash algorithm): %s\n", argv[1]);
         exit(1);
  }
  
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, argv[2], strlen(argv[2]));
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);
  
  // show hash values of a message
  printf("Digest is: ");
  for (i = 0; i < md_len; i++)
         printf("%02x", md_value[i]);
  printf("\n");
  
  return 0;
}

