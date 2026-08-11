// AES-32.H
#ifndef AES32_H
#define AES32_H

#ifdef AES32_STATIC
#define AES32_API
#elif defined(AES32_EXPORTS)
#define AES32_API __declspec(dllexport)
#else
#define AES32_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define AES32_KEY_SIZE 32
#define AES32_BLOCK_SIZE 32
#define AES32_ROUNDS 14
#define AES32_EXPANDED_KEY_SIZE 480

    AES32_API int aes32_init(const uint8_t* key, uint8_t* ctx);
    AES32_API void aes32_encrypt_block(const uint8_t* input, const uint8_t* ctx, uint8_t* output);
    AES32_API void aes32_decrypt_block(const uint8_t* input, const uint8_t* ctx, uint8_t* output);
    AES32_API int aes32_encrypt_cbc(const uint8_t* input, size_t input_len, const uint8_t* key, uint8_t** output, size_t* output_len);
    AES32_API int aes32_decrypt_cbc(const uint8_t* input, size_t input_len, const uint8_t* key, uint8_t** output, size_t* output_len);
    AES32_API int aes32_encrypt_text(const char* text, const uint8_t* key, char** output);
    AES32_API int aes32_decrypt_text(const char* b64text, const uint8_t* key, char** output);
    AES32_API int aes32_encrypt_file(const char* input_path, const char* output_path, const uint8_t* key);
    AES32_API int aes32_decrypt_file(const char* input_path, const char* output_path, const uint8_t* key);
    AES32_API void aes32_generate_key(uint8_t* key);
    AES32_API void aes32_key_to_hex(const uint8_t* key, char* hex);
    AES32_API int aes32_hex_to_key(const char* hex, uint8_t* key);
    AES32_API void aes32_free(void* ptr);

#ifdef __cplusplus
}
#endif

#endif // AES32_H