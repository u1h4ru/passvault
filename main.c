#include "common.h"
#include "cipher_utils.h"
#include "file_io.h"
#include <unistd.h>

void print_usage_msg(char *argv[]);
char* read_input_str();
void remove_newline_char(char* str_buffer);

int main(int argc, char *argv[])
{
    char* filename = NULL;

    bool e_flag = false;
    bool d_flag = false;

    int opt;
    while ((opt = getopt(argc, argv, "edf:")) != -1) {
        switch (opt) {
            case 'e':
                e_flag = true;
                break;
            case 'd':
                d_flag = true;
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
        printf("input the password: ");
        char* password = read_input_str();
        printf("%s", password);
        
        printf("input the master password: ");
        char* master_pw = read_input_str();
        printf("%s", master_pw);

        char *encrypted_str = encrypt(password, master_pw);
        printf("encrypted text: %s\n", encrypted_str);
        write_cipher_to_file(filename, encrypted_str);
       
        free(password);
        free(master_pw);
    } else {  // decrypt
        printf("input the master password: ");
        char* master_pw = read_input_str();
        printf("%s", master_pw);
            
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

        free(master_pw);
    }
    
    return 0;
}

void print_usage_msg(char *argv[]) 
{
    fprintf(stderr, "Usage: %s [-ed] [-f filename]\n", argv[0]);
}

char* read_input_str()
{
    char* buffer = malloc(sizeof(char) * 255);
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        remove_newline_char(buffer);
    }
    return buffer;
}

void remove_newline_char(char* str_buffer)
{
    char* newline = strchr(str_buffer, '\n');
    if (newline != NULL) {
        *newline = '\0';
    }
}
