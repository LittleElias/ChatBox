// aes32.c - AES-32 encryption library implementation
#define AES32_EXPORTS
#include "AES-32.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static const uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

static const uint8_t rcon[15] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D
};

static const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static uint8_t gmul2(uint8_t a) {
    uint8_t r = (uint8_t)(a << 1);
    if (a & 0x80) r ^= 0x1B;
    return r;
}

static uint8_t gmul3(uint8_t a) {
    return gmul2(a) ^ a;
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

static void sub_bytes(uint8_t* state) {
    for (int i = 0; i < AES32_BLOCK_SIZE; i++) state[i] = sbox[state[i]];
}

static void inv_sub_bytes(uint8_t* state) {
    for (int i = 0; i < AES32_BLOCK_SIZE; i++) state[i] = inv_sbox[state[i]];
}

static void shift_rows(uint8_t* state) {
    uint8_t temp[AES32_BLOCK_SIZE];
    for (int c = 0; c < 8; c++) temp[c * 4 + 0] = state[c * 4 + 0];
    for (int c = 0; c < 8; c++) temp[c * 4 + 1] = state[((c + 1) % 8) * 4 + 1];
    for (int c = 0; c < 8; c++) temp[c * 4 + 2] = state[((c + 3) % 8) * 4 + 2];
    for (int c = 0; c < 8; c++) temp[c * 4 + 3] = state[((c + 4) % 8) * 4 + 3];
    memcpy(state, temp, AES32_BLOCK_SIZE);
}

static void inv_shift_rows(uint8_t* state) {
    uint8_t temp[AES32_BLOCK_SIZE];
    for (int c = 0; c < 8; c++) temp[c * 4 + 0] = state[c * 4 + 0];
    for (int c = 0; c < 8; c++) temp[c * 4 + 1] = state[((c + 7) % 8) * 4 + 1];
    for (int c = 0; c < 8; c++) temp[c * 4 + 2] = state[((c + 5) % 8) * 4 + 2];
    for (int c = 0; c < 8; c++) temp[c * 4 + 3] = state[((c + 4) % 8) * 4 + 3];
    memcpy(state, temp, AES32_BLOCK_SIZE);
}

static void mix_columns(uint8_t* state) {
    for (int c = 0; c < 8; c++) {
        int idx = c * 4;
        uint8_t a0 = state[idx + 0], a1 = state[idx + 1];
        uint8_t a2 = state[idx + 2], a3 = state[idx + 3];
        state[idx + 0] = gmul(2, a0) ^ gmul(3, a1) ^ a2 ^ a3;
        state[idx + 1] = a0 ^ gmul(2, a1) ^ gmul(3, a2) ^ a3;
        state[idx + 2] = a0 ^ a1 ^ gmul(2, a2) ^ gmul(3, a3);
        state[idx + 3] = gmul(3, a0) ^ a1 ^ a2 ^ gmul(2, a3);
    }
}

static void inv_mix_columns(uint8_t* state) {
    for (int c = 0; c < 8; c++) {
        int idx = c * 4;
        uint8_t a0 = state[idx + 0], a1 = state[idx + 1];
        uint8_t a2 = state[idx + 2], a3 = state[idx + 3];
        state[idx + 0] = gmul(0x0E, a0) ^ gmul(0x0B, a1) ^ gmul(0x0D, a2) ^ gmul(0x09, a3);
        state[idx + 1] = gmul(0x09, a0) ^ gmul(0x0E, a1) ^ gmul(0x0B, a2) ^ gmul(0x0D, a3);
        state[idx + 2] = gmul(0x0D, a0) ^ gmul(0x09, a1) ^ gmul(0x0E, a2) ^ gmul(0x0B, a3);
        state[idx + 3] = gmul(0x0B, a0) ^ gmul(0x0D, a1) ^ gmul(0x09, a2) ^ gmul(0x0E, a3);
    }
}

static void add_round_key(uint8_t* state, const uint8_t* round_key) {
    for (int i = 0; i < AES32_BLOCK_SIZE; i++) state[i] ^= round_key[i];
}

static void key_expansion(const uint8_t* key, uint8_t* expanded_key) {
    memcpy(expanded_key, key, AES32_KEY_SIZE);
    uint8_t temp[4];
    int generated = AES32_KEY_SIZE;
    int rcon_idx = 1;

    while (generated < AES32_EXPANDED_KEY_SIZE) {
        for (int i = 0; i < 4; i++) temp[i] = expanded_key[generated - 4 + i];
        if (generated % AES32_KEY_SIZE == 0) {
            uint8_t t = temp[0];
            for (int i = 0; i < 3; i++) temp[i] = temp[i + 1];
            temp[3] = t;
            for (int i = 0; i < 4; i++) temp[i] = sbox[temp[i]];
            temp[0] ^= rcon[rcon_idx++];
        }
        for (int i = 0; i < 4; i++) {
            expanded_key[generated] = expanded_key[generated - AES32_KEY_SIZE] ^ temp[i];
            generated++;
        }
        for (int j = 0; j < 7; j++) {
            for (int i = 0; i < 4; i++) {
                expanded_key[generated] = expanded_key[generated - AES32_KEY_SIZE] ^ expanded_key[generated - 4];
                generated++;
            }
        }
    }
}

AES32_API int aes32_init(const uint8_t* key, uint8_t* ctx) {
    if (!key || !ctx) return -1;
    key_expansion(key, ctx);
    return 0;
}

AES32_API void aes32_encrypt_block(const uint8_t* input, const uint8_t* ctx, uint8_t* output) {
    uint8_t state[AES32_BLOCK_SIZE];
    memcpy(state, input, AES32_BLOCK_SIZE);
    add_round_key(state, ctx);
    for (int round = 1; round <= AES32_ROUNDS; round++) {
        sub_bytes(state);
        shift_rows(state);
        if (round < AES32_ROUNDS) mix_columns(state);
        add_round_key(state, ctx + round * AES32_BLOCK_SIZE);
    }
    memcpy(output, state, AES32_BLOCK_SIZE);
}

AES32_API void aes32_decrypt_block(const uint8_t* input, const uint8_t* ctx, uint8_t* output) {
    uint8_t state[AES32_BLOCK_SIZE];
    memcpy(state, input, AES32_BLOCK_SIZE);
    add_round_key(state, ctx + AES32_ROUNDS * AES32_BLOCK_SIZE);
    for (int round = AES32_ROUNDS - 1; round >= 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, ctx + round * AES32_BLOCK_SIZE);
        if (round > 0) inv_mix_columns(state);
    }
    memcpy(output, state, AES32_BLOCK_SIZE);
}

AES32_API int aes32_encrypt_cbc(const uint8_t* input, size_t input_len, const uint8_t* key, uint8_t** output, size_t* output_len) {
    if (!input || !key || !output || !output_len || input_len == 0) return -1;
    size_t pad_len = AES32_BLOCK_SIZE - (input_len % AES32_BLOCK_SIZE);
    size_t total_len = input_len + pad_len;
    *output_len = AES32_BLOCK_SIZE + total_len;
    *output = (uint8_t*)malloc(*output_len);
    if (!*output) return -1;

    uint8_t iv[AES32_BLOCK_SIZE];
    for (int i = 0; i < AES32_BLOCK_SIZE; i++) iv[i] = (uint8_t)(rand() % 256);
    memcpy(*output, iv, AES32_BLOCK_SIZE);

    uint8_t expanded_key[AES32_EXPANDED_KEY_SIZE];
    aes32_init(key, expanded_key);

    uint8_t* padded = (uint8_t*)malloc(total_len);
    if (!padded) { free(*output); return -1; }
    memcpy(padded, input, input_len);
    for (size_t i = input_len; i < total_len; i++) padded[i] = (uint8_t)pad_len;

    uint8_t prev[AES32_BLOCK_SIZE];
    memcpy(prev, iv, AES32_BLOCK_SIZE);
    for (size_t offset = 0; offset < total_len; offset += AES32_BLOCK_SIZE) {
        uint8_t block[AES32_BLOCK_SIZE];
        for (int i = 0; i < AES32_BLOCK_SIZE; i++) block[i] = padded[offset + i] ^ prev[i];
        aes32_encrypt_block(block, expanded_key, *output + AES32_BLOCK_SIZE + offset);
        memcpy(prev, *output + AES32_BLOCK_SIZE + offset, AES32_BLOCK_SIZE);
    }
    free(padded);
    return 0;
}

AES32_API int aes32_decrypt_cbc(const uint8_t* input, size_t input_len, const uint8_t* key, uint8_t** output, size_t* output_len) {
    if (!input || !key || !output || !output_len || input_len < AES32_BLOCK_SIZE * 2 || input_len % AES32_BLOCK_SIZE != 0) return -1;
    uint8_t iv[AES32_BLOCK_SIZE];
    memcpy(iv, input, AES32_BLOCK_SIZE);
    size_t cipher_len = input_len - AES32_BLOCK_SIZE;
    *output = (uint8_t*)malloc(cipher_len);
    if (!*output) return -1;

    uint8_t expanded_key[AES32_EXPANDED_KEY_SIZE];
    aes32_init(key, expanded_key);

    uint8_t prev[AES32_BLOCK_SIZE];
    memcpy(prev, iv, AES32_BLOCK_SIZE);
    for (size_t offset = 0; offset < cipher_len; offset += AES32_BLOCK_SIZE) {
        uint8_t decrypted[AES32_BLOCK_SIZE];
        aes32_decrypt_block(input + AES32_BLOCK_SIZE + offset, expanded_key, decrypted);
        for (int i = 0; i < AES32_BLOCK_SIZE; i++) (*output)[offset + i] = decrypted[i] ^ prev[i];
        memcpy(prev, input + AES32_BLOCK_SIZE + offset, AES32_BLOCK_SIZE);
    }
    uint8_t pad_val = (*output)[cipher_len - 1];
    *output_len = (pad_val > 0 && pad_val <= AES32_BLOCK_SIZE) ? cipher_len - pad_val : cipher_len;
    return 0;
}

static char* base64_encode(const uint8_t* data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char* out = (char*)malloc(out_len + 1);
    if (!out) return NULL;
    size_t i, j;
    for (i = 0, j = 0; i < len; ) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t t = (a << 16) | (b << 8) | c;
        out[j++] = b64_chars[(t >> 18) & 0x3F];
        out[j++] = b64_chars[(t >> 12) & 0x3F];
        out[j++] = b64_chars[(t >> 6) & 0x3F];
        out[j++] = b64_chars[t & 0x3F];
    }
    if (len % 3 == 1) { out[j-2] = '='; out[j-1] = '='; }
    else if (len % 3 == 2) out[j-1] = '=';
    out[j] = '\0';
    return out;
}

static uint8_t* base64_decode(const char* str, size_t* out_len) {
    size_t len = strlen(str);
    if (len % 4) return NULL;
    size_t max = len / 4 * 3;
    uint8_t* out = (uint8_t*)malloc(max);
    if (!out) return NULL;
    size_t i, j = 0;
    uint32_t val = 0;
    int bits = 0;
    for (i = 0; i < len; i++) {
        char c = str[i];
        if (c == '=') break;
        const char* p = strchr(b64_chars, c);
        if (!p) { free(out); return NULL; }
        val = (val << 6) | (uint32_t)(p - b64_chars);
        bits += 6;
        if (bits >= 8) { bits -= 8; out[j++] = (val >> bits) & 0xFF; }
    }
    *out_len = j;
    return out;
}

AES32_API int aes32_encrypt_text(const char* text, const uint8_t* key, char** output) {
    if (!text || !key || !output) return -1;
    size_t text_len = strlen(text);
    uint8_t* encrypted = NULL;
    size_t encrypted_len = 0;
    int ret = aes32_encrypt_cbc((const uint8_t*)text, text_len, key, &encrypted, &encrypted_len);
    if (ret != 0) return ret;
    *output = base64_encode(encrypted, encrypted_len);
    free(encrypted);
    return *output ? 0 : -1;
}

AES32_API int aes32_decrypt_text(const char* b64text, const uint8_t* key, char** output) {
    if (!b64text || !key || !output) return -1;
    size_t data_len;
    uint8_t* data = base64_decode(b64text, &data_len);
    if (!data) return -1;
    uint8_t* decrypted = NULL;
    size_t decrypted_len = 0;
    int ret = aes32_decrypt_cbc(data, data_len, key, &decrypted, &decrypted_len);
    free(data);
    if (ret != 0) return ret;
    *output = (char*)malloc(decrypted_len + 1);
    if (!*output) { free(decrypted); return -1; }
    memcpy(*output, decrypted, decrypted_len);
    (*output)[decrypted_len] = '\0';
    free(decrypted);
    return 0;
}

AES32_API int aes32_encrypt_file(const char* input_path, const char* output_path, const uint8_t* key) {
    if (!input_path || !output_path || !key) return -1;
    FILE* fin = fopen(input_path, "rb");
    if (!fin) return -1;
    fseek(fin, 0, SEEK_END);
    size_t file_size = (size_t)ftell(fin);
    fseek(fin, 0, SEEK_SET);
    uint8_t* plaintext = (uint8_t*)malloc(file_size);
    if (!plaintext) { fclose(fin); return -1; }
    if (fread(plaintext, 1, file_size, fin) != file_size) { free(plaintext); fclose(fin); return -1; }
    fclose(fin);
    uint8_t* ciphertext = NULL;
    size_t ciphertext_len = 0;
    int ret = aes32_encrypt_cbc(plaintext, file_size, key, &ciphertext, &ciphertext_len);
    free(plaintext);
    if (ret != 0) return ret;
    FILE* fout = fopen(output_path, "wb");
    if (!fout) { free(ciphertext); return -1; }
    size_t written = fwrite(ciphertext, 1, ciphertext_len, fout);
    fclose(fout);
    free(ciphertext);
    return written == ciphertext_len ? 0 : -1;
}

AES32_API int aes32_decrypt_file(const char* input_path, const char* output_path, const uint8_t* key) {
    if (!input_path || !output_path || !key) return -1;
    FILE* fin = fopen(input_path, "rb");
    if (!fin) return -1;
    fseek(fin, 0, SEEK_END);
    size_t file_size = (size_t)ftell(fin);
    fseek(fin, 0, SEEK_SET);
    uint8_t* ciphertext = (uint8_t*)malloc(file_size);
    if (!ciphertext) { fclose(fin); return -1; }
    if (fread(ciphertext, 1, file_size, fin) != file_size) { free(ciphertext); fclose(fin); return -1; }
    fclose(fin);
    uint8_t* plaintext = NULL;
    size_t plaintext_len = 0;
    int ret = aes32_decrypt_cbc(ciphertext, file_size, key, &plaintext, &plaintext_len);
    free(ciphertext);
    if (ret != 0) return ret;
    FILE* fout = fopen(output_path, "wb");
    if (!fout) { free(plaintext); return -1; }
    size_t written = fwrite(plaintext, 1, plaintext_len, fout);
    fclose(fout);
    free(plaintext);
    return written == plaintext_len ? 0 : -1;
}

AES32_API void aes32_generate_key(uint8_t* key) {
    for (int i = 0; i < AES32_KEY_SIZE; i++) key[i] = (uint8_t)(rand() % 256);
}

AES32_API void aes32_key_to_hex(const uint8_t* key, char* hex) {
    for (int i = 0; i < AES32_KEY_SIZE; i++) sprintf(hex + i * 2, "%02X", key[i]);
    hex[64] = '\0';
}

AES32_API int aes32_hex_to_key(const char* hex, uint8_t* key) {
    if (strlen(hex) != 64) return -1;
    for (int i = 0; i < AES32_KEY_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2X", &byte) != 1) return -1;
        key[i] = (uint8_t)byte;
    }
    return 0;
}

AES32_API void aes32_free(void* ptr) {
    free(ptr);
}