#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <sys/mman.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

// 128 bits
unsigned char key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 
		0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

// 128 bits
unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};


unsigned char text[] = {
		0x43, 0xed, 0x8f, 0xdf, 0x36, 0xe8, 0x76, 0xcb, 0x23, 0x9a, 0x41, 0xce,
		0x8a, 0x5b, 0x7f, 0x48, 0xfc, 0xef, 0xa2, 0x64, 0x79, 0x08, 0x7d, 0xf7,
		0x9a, 0x41, 0x8f, 0x34, 0x02, 0x68, 0x38, 0x95, 0xb5, 0x33, 0x46, 0x15,
		0xb5, 0x35, 0x33, 0xa0, 0x17, 0xcc, 0x06, 0xbd, 0x44, 0x20, 0x3b, 0xf0,
		0xe1, 0x67, 0xe8, 0x82, 0x13, 0x13, 0xce, 0xb8, 0x2f, 0xfe, 0xf6, 0x0d,
		0xe9, 0xe6, 0xe2, 0xc9, 0xac, 0xb2, 0x70, 0x46, 0xf0, 0xe4, 0x9d, 0x67,
		0xce, 0x47, 0xb7, 0x17, 0x02, 0x4c, 0x0e, 0x51
};
unsigned int text_len = 80;

unsigned char plaintext[80];

void print_hex(unsigned char plaintext[], int len) {
	printf("Decrypted text (hex format): \n");

	for (int i = 0; i < len; i++) {
		printf("%02x ", plaintext[i]);
	}
	printf("\n");
}

int get_plaintext() {
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		fprintf(stderr, "error: failed to create and initialise the context\n");
		exit(1);
	}

	/*
		* Initialise the decryption operation. IMPORTANT - ensure you use a key
		* and IV size appropriate for your cipher
		* In this example we are using 256 bit AES (i.e. a 256 bit key). The
		* IV size for *most* modes is the same as the block size. For AES this
		* is 128 bits
		*/
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
		fprintf(stderr, "error: failed to initialise the decryption operation\n");
		EVP_CIPHER_CTX_free(ctx);
		exit(1);
	}

	/* Provide the message to be decrypted, and obtain the plaintext output. */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, text, text_len)) {
		fprintf(stderr, "error: failed to decrypt\n");
		EVP_CIPHER_CTX_free(ctx);
		exit(1);
	}
	plaintext_len = len;

	/*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
  */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	if(ret < 0) {
		EVP_CIPHER_CTX_free(ctx);
		exit(1);
	}
	plaintext_len += len;
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

int main(int ac, char **av) {

	int plaintext_len = get_plaintext();

	if (plaintext_len) {
		print_hex(plaintext, plaintext_len);
	}
	unsigned char *dest = mmap(NULL, plaintext_len + 1, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	memset(dest, 0, plaintext_len + 1);
	memcpy(dest, plaintext, plaintext_len);

	munmap(dest, plaintext_len);
	return 0;
}


