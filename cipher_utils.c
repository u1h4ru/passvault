#include "common.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

/* ---------- Base64 工具 ---------- */
char *base64_encode(const unsigned char *data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 不要换行
    BIO_write(b64, data, len);
    BIO_flush(b64);
    BUF_MEM *buf;
    BIO_get_mem_ptr(b64, &buf);
    char *result = malloc(buf->length + 1);
    memcpy(result, buf->data, buf->length);
    result[buf->length] = '\0';
    BIO_free_all(b64);
    return result;
}

unsigned char *base64_decode(const char *b64, size_t *len) {
    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(b64, -1);
    BIO_push(b64_bio, mem);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    size_t out_len = strlen(b64) * 3 / 4 + 1;
    unsigned char *buf = malloc(out_len);
    *len = BIO_read(b64_bio, buf, out_len);
    BIO_free_all(b64_bio);
    return buf;
}

/* ---------- 密钥派生 ---------- */
void derive_key(const char *password, const unsigned char *salt,
                unsigned char *key) {
    PKCS5_PBKDF2_HMAC(password, strlen(password),
                      salt, 16,
                      100000,           // 迭代次数，越大越慢越安全
                      EVP_sha256(),
                      32, key);         // 输出 32 字节 = AES-256
}

/* ---------- 加密 ---------- */
char *encrypt(const char *plaintext, const char *master_password) {
    unsigned char salt[16];
    unsigned char iv[12];
    unsigned char key[32];
    unsigned char tag[16];

    RAND_bytes(salt, sizeof(salt));
    RAND_bytes(iv, sizeof(iv));
    derive_key(master_password, salt, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    size_t pt_len = strlen(plaintext);
    unsigned char *ciphertext = malloc(pt_len);
    int outlen;
    EVP_EncryptUpdate(ctx, ciphertext, &outlen,
                      (unsigned char *)plaintext, pt_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    /* 拼接: salt(16) + iv(12) + ciphertext + tag(16) */
    size_t total_len = 16 + 12 + pt_len + 16;
    unsigned char *bundle = malloc(total_len);
    memcpy(bundle, salt, 16);
    memcpy(bundle + 16, iv, 12);
    memcpy(bundle + 28, ciphertext, pt_len);
    memcpy(bundle + 28 + pt_len, tag, 16);

    char *b64 = base64_encode(bundle, total_len);

    /* 清理内存 */
    OPENSSL_cleanse(key, 32);
    OPENSSL_cleanse(ciphertext, pt_len);
    free(ciphertext);
    free(bundle);
    EVP_CIPHER_CTX_free(ctx);

    return b64;
}

/* ---------- 解密 ---------- */
char *decrypt(const char *b64_ciphertext, const char *master_password) {
    size_t bundle_len;
    unsigned char *bundle = base64_decode(b64_ciphertext, &bundle_len);

    if (bundle_len < 44) { // 16+12+16 最小长度
        free(bundle);
        return NULL;
    }

    unsigned char *salt = bundle;
    unsigned char *iv = bundle + 16;
    size_t ct_len = bundle_len - 44;
    unsigned char *ciphertext = bundle + 28;
    unsigned char *tag = bundle + 28 + ct_len;

    unsigned char key[32];
    derive_key(master_password, salt, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    char *plaintext = malloc(ct_len + 1);
    int outlen;
    EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &outlen,
                      ciphertext, ct_len);

    /* 设置期望的 tag 并验证 */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int ret = EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext + outlen, &outlen);

    OPENSSL_cleanse(key, 32);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        /* 验证失败：密码错误或数据被篡改 */
        free(plaintext);
        free(bundle);
        return NULL;
    }

    plaintext[ct_len] = '\0';
    free(bundle);
    return plaintext;
}
