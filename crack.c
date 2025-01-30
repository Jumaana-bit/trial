#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define BLOCK_SIZE 16

// Convert hex string to bytes
void hex_to_bytes(const char *hex, unsigned char *bytes, int len) {
    for (int i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

// Try decrypting with a given key
int try_decrypt(const unsigned char *key, const unsigned char *ciphertext, unsigned char *decrypted, int ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[BLOCK_SIZE] = {0}; // IV is all zeros
    int len, decrypted_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, decrypted, &len, ciphertext, ciphertext_len);
    decrypted_len = len;

    EVP_DecryptFinal_ex(ctx, decrypted + len, &len);
    decrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return decrypted_len;
}

int main() {
    const char *plaintext = "This is a top secret."; // Known plaintext
    unsigned char ciphertext[BLOCK_SIZE * 2];
    const char *ciphertext_hex = "8d20e5056a8d24d0462ce74e4904c1b5"
                                 "13e10d1df4a2ef2ad4540fae1ca0aaf9";
    
    hex_to_bytes(ciphertext_hex, ciphertext, sizeof(ciphertext));

    FILE *dict = fopen("dictionary.txt", "r");
    if (!dict) {
        perror("Failed to open dictionary");
        return 1;
    }

    char word[17]; // Buffer for words (max 16 + null terminator)
    unsigned char key[BLOCK_SIZE];
    unsigned char decrypted[BLOCK_SIZE * 2];

    while (fscanf(dict, "%16s", word) == 1) {
        memset(key, 0x20, BLOCK_SIZE); // Fill key with spaces
        memcpy(key, word, strlen(word)); // Copy word into key

        int decrypted_len = try_decrypt(key, ciphertext, decrypted, sizeof(ciphertext));
        decrypted[decrypted_len] = '\0'; // Null-terminate result

        if (strncmp((char *)decrypted, plaintext, decrypted_len) == 0) {
            printf("Found key: %s\n", word);
            break;
        }
    }

    fclose(dict);
    return 0;
}
