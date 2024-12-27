#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include <cjson/cJSON.h>

#include "parse.h"


char *read_file(const char *filepath) {

	FILE *file = fopen(filepath, "r");
	if (!file) {
		perror("fopen failed");
		exit(1);
	}

	fseek(file, 0, SEEK_END);
	size_t size = ftell(file);
	rewind(file);

	char *buffer = malloc(size);
	if (!buffer) {
		perror("malloc failed");
		exit(1);
	}

	fread(buffer, 1, size, file);
	fclose(file);
	buffer[size] = 0;
	return buffer;
}


int parse_samourai_backup_version(cJSON *json) {

	cJSON *version;

	version = cJSON_GetObjectItemCaseSensitive(json, "version");
	if (!cJSON_IsNumber(version)) {
		fprintf(stderr, "Version is not a number\n");
		exit(1);
	}

	if (version->valueint != 2) {
		fprintf(stderr, "Only version 2 is supported\n");
		exit(1);
	}

	return version->valueint;
}


char *parse_samourai_backup_payload(cJSON *json) {

	char *result;
	cJSON *payload;

	payload = cJSON_GetObjectItemCaseSensitive(json, "payload");
	if (!cJSON_IsString(payload)) {
		fprintf(stderr, "Payload is not a string\n");
		exit(1);
	}

	if (!payload->valuestring) {
		fprintf(stderr, "Payload is null\n");
		exit(1);
	}

	if (!*payload->valuestring) {
		fprintf(stderr, "Payload is empty\n");
		exit(1);
	}

	result = strdup(payload->valuestring);
	if (!result) {
		perror("strdup failed");
		exit(1);
	}

	return result;
}


bool parse_samourai_backup_external(cJSON *json) {

	cJSON *external;

	external = cJSON_GetObjectItemCaseSensitive(json, "external");
	if (!cJSON_IsBool(external)) {
		fprintf(stderr, "External is not a boolean\n");
		exit(1);
	}

	return cJSON_IsTrue(external);
}


struct samourai_backup *parse_samourai_backup(const char *backup_file) {

	char *json_string = read_file(backup_file);
	cJSON *json = cJSON_Parse(json_string);
	if (!json) {
		fprintf(stderr, "cJSON_Parse failed\n");
		exit(1);
	}

	struct samourai_backup *backup;
	backup = malloc(sizeof(*backup));
	if (!backup) {
		perror("malloc failed");
		exit(1);
	}
	memset(backup, 0, sizeof(*backup));
	backup->version = parse_samourai_backup_version(json);
	backup->payload = parse_samourai_backup_payload(json);
	backup->external = parse_samourai_backup_external(json);
	return backup;
}


uint8_t *base64_decode(const char *input) {
	BIO *bio, *b64;
	size_t input_len;
	char *output;

	input_len = strlen(input);
	output = malloc(input_len);
	if (!output) {
		perror("malloc failed");
	exit(1);
	}

	bio = BIO_new_mem_buf(input, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	if (!strchr(input, '\n'))
		BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	BIO_read(bio, output, input_len);

	BIO_free_all(bio);
	return output;
}
