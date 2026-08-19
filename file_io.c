#include "common.h"

int write_cipher_to_file(const char* filename, const char* b64_cipher)
{
	FILE *fp = fopen(filename, "w");
	if (fp == NULL) {
		return -1;
	}

	fprintf(fp, "%s\n", b64_cipher);

	fclose(fp);

	return 0;
}

char *read_cipher_from_file(const char* filename)
{

	FILE* fp = fopen(filename, "r");
	if (fp == NULL) {
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (size <= 0) {
		fclose(fp);
		fprintf(stderr, "File is empty!\n");
		return NULL;
	}
	
	char *buf = malloc(size + 1);
	if (!buf) {
		fclose(fp);
		return NULL;
	}

	
	fread(buf, 1, size, fp);
	buf[size] = '\0';
	
	fclose(fp);

	buf[strcspn(buf, "\n")] = '\0';
	
	return buf;
}
