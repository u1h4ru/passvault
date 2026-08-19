#include "common.h"
#include "cipher_utils.h"
#include "file_io.h"
#include <unistd.h>

void print_usage_msg(char *argv[]);

int main(int argc, char *argv[])
{
	char* master_pw = NULL;
	char* password = NULL;
	char* filename = NULL;

	bool e_flag = false;
	bool d_flag = false;

	int opt;
	while ((opt = getopt(argc, argv, "edp:m:f:")) != -1) {
		switch (opt) {
			case 'e':
				e_flag = true;
				break;
			case 'd':
				d_flag = true;
				break;
			case 'p':
				password = optarg;
				break;
			case 'm':
				master_pw = optarg;
				break;
			case 'f':
				filename = optarg;	
				break;
			case '?':
				print_usage_msg(argv);
            			return 1;
			default:
				abort();

		}
	}

	if ((!e_flag && !d_flag) || (e_flag && d_flag)) {
		printf("Please use one and only one of '-e' and '-d'!\n");
		print_usage_msg(argv);
		return -1;
	}

	if (filename == NULL) {
		printf("Please point the file by -f option!\n");
		print_usage_msg(argv);
		return -1;
	}

	if (e_flag) {  // encrypt
		char *encrypted_str = encrypt(password, master_pw);
		printf("encrypted text: %s\n", encrypted_str);
		write_cipher_to_file(filename, encrypted_str);
	} else { // decrypt
		char *encrypted_str = read_cipher_from_file(filename);
		printf("encrypted text: %s\n", encrypted_str);
		char *decrypted_str = decrypt(encrypted_str, master_pw);
		free(encrypted_str);
		printf("-------------------------------------------------------------------------------------\n");
		if (decrypted_str != NULL) {
			printf("decrypted text: %s\n", decrypted_str);
			free(decrypted_str);
		} else {
			printf("decrypt failed: master password or encrypted info was damaged\n");
		}
	}
	
	return 0;
}

void print_usage_msg(char *argv[]) 
{
	fprintf(stderr, "Usage: %s [-ed] [-p password] [-m master_pw] [-f filename]\n", argv[0]);
}
