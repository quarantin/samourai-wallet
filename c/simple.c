#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define DERIVED_LEN 48

void hexdump(uint8_t *data, size_t size) {
	for (int i = 0; i < size; i++) {
		if (i && !(i % 4))
			printf("\n");
		printf("%02x ", data[i]);
	}
	printf("\n\n");
}

int main() {
	uint8_t derived[DERIVED_LEN];
	int iterations = 1;
	char *passphrase = "";
	uint8_t salt[8];

	memset(salt, 0, sizeof(salt));

	if (!PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt, 0, iterations, EVP_sha256(), DERIVED_LEN, derived)) {
		fprintf(stderr, "Key derivation failed.\n");
		exit(1);
	}

	uint8_t key[32];
	uint8_t iv[16];

	memcpy(key, derived, 32);
	memcpy(iv, derived + 32, 16);

	printf("KEY\n");
	hexdump(key, 32);

	printf("IV\n");
	hexdump(iv, 16);
}
