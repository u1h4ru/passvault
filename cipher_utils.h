char *base64_encode(const unsigned char *data, size_t len);
unsigned char *base64_decode(const char *b64, size_t *len);
void derive_key(const char *password, const unsigned char *salt, unsigned char *key);
char *encrypt(const char *plaintext, const char *master_password);
char *decrypt(const char *b64_ciphertext, const char *master_password);
