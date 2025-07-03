#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <termios.h>

#define BLOCK_SIZE 64
#define ROUNDS 20
#define SALT_SIZE 16

// Rotate left
uint8_t rotate_left(uint8_t val, int shift) {
    return (val << shift) | (val >> (8 - shift));
}

// XOR two blocks
void xor_blocks(uint8_t *out, const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < BLOCK_SIZE; ++i)
        out[i] = a[i] ^ b[i];
}

// Key schedule
void key_schedule(uint64_t *master_key, uint64_t round_keys[ROUNDS][8]) {
    for (int r = 0; r < ROUNDS; ++r)
        for (int i = 0; i < 8; ++i)
            round_keys[r][i] = (master_key[i] << ((r + i) % 64)) ^ (0xA5A5A5A5A5A5A5A5ULL + r);
}

// TitanLock block cipher
void titan_encrypt(uint8_t *block, uint64_t round_keys[ROUNDS][8]) {
    for (int r = 0; r < ROUNDS; ++r) {
        for (int i = 0; i < 8; ++i)
            ((uint64_t*)block)[i] ^= round_keys[r][i];
        for (int i = 0; i < BLOCK_SIZE; ++i)
            block[i] = rotate_left(block[i], r % 8) ^ (r * i);
    }
}

// Padding (PKCS#7)
size_t pad(uint8_t *in, size_t len, uint8_t *out) {
    size_t pad_len = BLOCK_SIZE - (len % BLOCK_SIZE);
    memcpy(out, in, len);
    for (size_t i = 0; i < pad_len; ++i)
        out[len + i] = pad_len;
    return len + pad_len;
}

// MAC (EVP SHA-512)
int compute_mac(uint8_t *data, size_t len, uint8_t *key, uint8_t *mac_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, key, BLOCK_SIZE) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, mac_out, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    EVP_MD_CTX_free(ctx);
    return 1;
}

// CBC encryption
void encrypt_cbc(uint8_t *plaintext, uint8_t *ciphertext, size_t blocks,
                 uint64_t round_keys[ROUNDS][8], uint8_t *iv) {
    uint8_t block[BLOCK_SIZE];
    for (size_t i = 0; i < blocks; ++i) {
        xor_blocks(block, &plaintext[i * BLOCK_SIZE], iv);
        titan_encrypt(block, round_keys);
        memcpy(&ciphertext[i * BLOCK_SIZE], block, BLOCK_SIZE);
        memcpy(iv, block, BLOCK_SIZE);
    }
}

// Secure password prompt
void prompt_password(char *buffer, size_t size) {
    struct termios oldt, newt;
    printf("Enter password: ");
    fflush(stdout);
    tcgetattr(0, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(0, TCSANOW, &newt);
    fgets(buffer, size, stdin);
    tcsetattr(0, TCSANOW, &oldt);
    printf("\n");
    buffer[strcspn(buffer, "\n")] = 0;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s -e|-d <input> <output>\n", argv[0]);
        return 1;
    }

    FILE *fin = fopen(argv[2], "rb");
    FILE *fout = fopen(argv[3], "wb");
    if (!fin || !fout) {
        perror("File error");
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    size_t len = ftell(fin);
    rewind(fin);
    uint8_t *input = malloc(len);
    fread(input, 1, len, fin);
    fclose(fin);

    // 🔐 Prompt for password
    char password[512];
    prompt_password(password, sizeof(password));

    // 🧂 Generate salt
    unsigned char salt[SALT_SIZE];
    RAND_bytes(salt, sizeof(salt));
    fwrite(salt, 1, SALT_SIZE, fout); // Save salt to output

    // 🔑 Derive key
    unsigned char key_bytes[BLOCK_SIZE];
    PKCS5_PBKDF2_HMAC(password, strlen(password),
                      salt, sizeof(salt),
                      100000, EVP_sha512(),
                      BLOCK_SIZE, key_bytes);

    uint64_t master_key[8];
    memcpy(master_key, key_bytes, BLOCK_SIZE);
    uint64_t round_keys[ROUNDS][8];
    key_schedule(master_key, round_keys);

    if (strcmp(argv[1], "-e") == 0) {
        size_t padded_len = ((len / BLOCK_SIZE) + 1) * BLOCK_SIZE;
        uint8_t *padded = malloc(padded_len);
        pad(input, len, padded);

        uint8_t *ciphertext = malloc(padded_len);
        uint8_t iv[BLOCK_SIZE];
        RAND_bytes(iv, BLOCK_SIZE);
        fwrite(iv, 1, BLOCK_SIZE, fout); // Save IV

        encrypt_cbc(padded, ciphertext, padded_len / BLOCK_SIZE, round_keys, iv);

        int mac_len = EVP_MD_size(EVP_sha512());
        uint8_t *mac = malloc(mac_len);
        if (!compute_mac(ciphertext, padded_len, key_bytes, mac)) {
            fprintf(stderr, "MAC generation failed.\n");
            free(padded); free(ciphertext); free(mac); free(input);
            fclose(fout);
            return 1;
        }

        fwrite(ciphertext, 1, padded_len, fout);
        fwrite(mac, 1, mac_len, fout);
        printf("✅ Encryption complete. Salt, IV, ciphertext, and MAC written.\n");

        free(padded); free(ciphertext); free(mac);
    } else {
        printf("⚠️ Decryption not implemented in this demo.\n");
    }

    free(input);
    fclose(fout);
    return 0;
}

