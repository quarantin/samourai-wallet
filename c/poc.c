#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include "parse.h"

#define SALTED "Salted__"

//#define ITERATIONS 15000
//FIXME: iteration count should be 15000, this is just for debug
#define ITERATIONS 1

#define DERIVED_LEN 48
// #define DERIVED_LEN 32


void hexdump(uint8_t *data, size_t size) {
	for (int i = 0; i < size; i++) {
		if (i && !(i % 4))
			printf("\n");
		printf("%02x ", data[i]);
	}
	printf("\n\n");
}


void derive_key(const char *passphrase, const uint8_t *salt, int iterations, uint8_t *key, uint8_t *iv) {

	uint8_t derived[DERIVED_LEN];

	if (!PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt, 8, iterations, EVP_sha256(), DERIVED_LEN, derived)) {
		fprintf(stderr, "Key derivation failed.\n");
		exit(1);
	}

	memcpy(key, derived, 32);
	memcpy(iv, derived + 32, 16);
	// memcpy(iv, derived, 16);
}


void aes_encrypt_first_block(const uint8_t *key, const uint8_t *iv, const uint8_t *plaintext, uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, 16);

    EVP_CIPHER_CTX_free(ctx);
}


int main(int argc, char **argv) {

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <samourai.txt> <passphrases.txt>\n", argv[0]);
		exit(1);
	}

	const char *backup_file = argv[1];
	const char *passphrase_file = argv[2];
	struct samourai_backup *backup = parse_samourai_backup(backup_file);
	uint8_t *encrypted_data = base64_decode(backup->payload);

	free(backup->payload);
	free(backup);

	if (memcmp(encrypted_data, SALTED, strlen(SALTED)) != 0) {
		fprintf(stderr, "Invalid file format: missing '" SALTED "' header.\n");
		free(encrypted_data);
		return 1;
	}

	uint8_t salt[8], expected_ciphertext[16];
	memcpy(salt, encrypted_data + 8, sizeof(salt));
	memcpy(expected_ciphertext, encrypted_data + 16, sizeof(expected_ciphertext));
	free(encrypted_data);

	char passphrase[BUFSIZ];
	FILE *file = fopen(passphrase_file, "r");
	if (!file) {
		perror("fopen failed");
		exit(1);
	}

	bool success = false;
	uint8_t key[32], iv[16], ciphertext[16], plaintext[16] = "{\"wallet\":{\"test";

	while (fgets(passphrase, sizeof(passphrase), file)) {

		size_t len = strlen(passphrase);
		if (len > 0 && passphrase[len - 1] == '\n')
			passphrase[len - 1] = 0;

		printf("PASSPHRASE (%ld)\n", strlen(passphrase));
		hexdump(passphrase, strlen(passphrase));

		printf("SALT (%d)\n", 8);
		hexdump(salt, 8);

		printf("ENCRYPTED (%d)\n", 16);
		hexdump(expected_ciphertext, 16);

		derive_key(passphrase, salt, ITERATIONS, key, iv);

		printf("KEY (%d)\n", 32);
		hexdump(key, 32);

		printf("IV (%d)\n", 16);
		hexdump(iv, 16);

		aes_encrypt_first_block(key, iv, plaintext, ciphertext);

		if (!memcmp(ciphertext, expected_ciphertext, sizeof(expected_ciphertext))) {
			success = true;
			printf("Passphrase is %s\n", passphrase);
			break;
		}
	}

	if (!success) {
		printf("Passphrase not found\n");
	}

	return 0;
}
