/*
 * main.c
 *
 *  Created on: 15 апр. 2025 г.
 *      Author: СЕРГЕЙ
 */

#include "main.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>

#define BLOCK_SIZE 16
#define MAX_KEY_LEN 32

void add_padding(BYTE *block, size_t data_len, size_t block_size) {
    BYTE pad_value = block_size - data_len;
    for (size_t i = data_len; i < block_size; i++) {
        block[i] = pad_value;
    }
}

int is_valid_padding(BYTE *block, size_t block_size) {
    BYTE pad_value = block[block_size - 1];
    if (pad_value > block_size || pad_value == 0) {
        return 0;
    }
    for (size_t i = block_size - pad_value; i < block_size; i++) {
        if (block[i] != pad_value) return 0;
    }
    return 1;
}

void parse_key(const char *key_str, BYTE *key, size_t key_len) {
    for (size_t i = 0; i < key_len; i++) {
        sscanf(key_str + 2 * i, "%2hhx", &key[i]);
    }
}

size_t remove_padding(BYTE *block, size_t block_size) {
    BYTE pad_value = block[block_size - 1];
    return block_size - pad_value;
}

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

unsigned long long h(UINT x, UINT *keys, int k) {
    unsigned long long result = x;
    for (int i = 0; i < k; i++) {
        result ^= (keys[i] + result);
    }
    return result;
}

void TwoFish_init(TwoFish *tf, BYTE *key, size_t length) {
    short N;
    if (length <= 16) {
        N = 128;
    } else if (length <= 24) {
        N = 192;
    } else {
        N = 256;
    }

    BYTE *temp_key = (BYTE *)malloc(N / 8);
    for (int i = 0; i < N / 8; i++) {
        temp_key[i] = (i < length) ? key[i] : 0;
    }

    tf->k = N / 64;

    UINT *Me = (UINT *)malloc(tf->k * sizeof(UINT));
    UINT *Mo = (UINT *)malloc(tf->k * sizeof(UINT));

    BYTE RS[4][8] = {
        {0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E},
        {0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5},
        {0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19},
        {0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03}
    };

    for (int c1 = 0, c2 = 0, i = 0; i < 2 * tf->k; i++) {
        UINT val = 0;
        for (int j = 0; j < 4; j++) {
            val |= (temp_key[4 * i + j] << (24 - 8 * j));
        }

        if (i % 2 == 0) {
            Me[c1++] = val;
        } else {
            Mo[c2++] = val;
        }
    }

    tf->SBox = (UINT *)malloc(tf->k * sizeof(UINT));
    for (int i = 0; i < tf->k; i++) {
        tf->SBox[tf->k - 1 - i] = 0;
        for (int j = 0; j < 4; j++) {
            UINT v = 0;
            for (int t = 0; t < 8; t++) {
                v += RS[j][t] * temp_key[8 * i + t];
            }
            tf->SBox[tf->k - 1 - i] += (v << (8 * j));
        }
    }

    UINT ro = (1 << 24) + (1 << 16) + (1 << 8) + 1;
    for (int i = 0; i < 20; i++) {
        unsigned long long A = h(2 * i * ro, Me, tf->k);
        unsigned long long B = h((2 * i + 1) * ro, Mo, tf->k);
        B = ROL(B, 8);
        tf->keys[2 * i] = (A + B) & 0xFFFFFFFF;
        tf->keys[2 * i + 1] = ROL(((A + 2 * B) & 0xFFFFFFFF), 9);
    }

    free(Me);
    free(Mo);
    free(temp_key);
}

void TwoFish_cleanup(TwoFish *tf) {
    free(tf->SBox);
}

BYTE* TwoFish_encrypt(TwoFish *tf, BYTE *plain) {
    UINT A = (plain[0] << 24) | (plain[1] << 16) | (plain[2] << 8) | plain[3];
    UINT B = (plain[4] << 24) | (plain[5] << 16) | (plain[6] << 8) | plain[7];
    UINT C = (plain[8] << 24) | (plain[9] << 16) | (plain[10] << 8) | plain[11];
    UINT D = (plain[12] << 24) | (plain[13] << 16) | (plain[14] << 8) | plain[15];

    A ^= tf->keys[0];
    B ^= tf->keys[1];
    C ^= tf->keys[2];
    D ^= tf->keys[3];

    for (int i = 0; i < 16; i++) {
        unsigned long long tA = h(A, tf->SBox, tf->k);
        unsigned long long tB = h(ROL(B, 8), tf->SBox, tf->k);

        D = ROL(D, 1);
        C ^= (tA + tB + tf->keys[2 * i + 8]) & 0xFFFFFFFF;
        D ^= (tA + 2 * tB + tf->keys[2 * i + 9]) & 0xFFFFFFFF;
        C = ROR(C, 1);

        if (i != 15) {
            UINT tmp = C;
            C = A;
            A = tmp;
            tmp = D;
            D = B;
            B = tmp;
        }
    }

    A ^= tf->keys[4];
    B ^= tf->keys[5];
    C ^= tf->keys[6];
    D ^= tf->keys[7];

    plain[0] = (A >> 24) & 0xFF;
    plain[1] = (A >> 16) & 0xFF;
    plain[2] = (A >> 8) & 0xFF;
    plain[3] = A & 0xFF;
    plain[4] = (B >> 24) & 0xFF;
    plain[5] = (B >> 16) & 0xFF;
    plain[6] = (B >> 8) & 0xFF;
    plain[7] = B & 0xFF;
    plain[8] = (C >> 24) & 0xFF;
    plain[9] = (C >> 16) & 0xFF;
    plain[10] = (C >> 8) & 0xFF;
    plain[11] = C & 0xFF;
    plain[12] = (D >> 24) & 0xFF;
    plain[13] = (D >> 16) & 0xFF;
    plain[14] = (D >> 8) & 0xFF;
    plain[15] = D & 0xFF;
    return plain;
}

BYTE* TwoFish_decrypt(TwoFish *tf, BYTE *cipher) {
    UINT A = (cipher[0] << 24) | (cipher[1] << 16) | (cipher[2] << 8) | cipher[3];
    UINT B = (cipher[4] << 24) | (cipher[5] << 16) | (cipher[6] << 8) | cipher[7];
    UINT C = (cipher[8] << 24) | (cipher[9] << 16) | (cipher[10] << 8) | cipher[11];
    UINT D = (cipher[12] << 24) | (cipher[13] << 16) | (cipher[14] << 8) | cipher[15];

    A ^= tf->keys[4];
    B ^= tf->keys[5];
    C ^= tf->keys[6];
    D ^= tf->keys[7];

    for (int i = 15; i >= 0; i--) {
        unsigned long long tA = h(A, tf->SBox, tf->k);
        unsigned long long tB = h(ROL(B, 8), tf->SBox, tf->k);

        C = ROL(C, 1);
        C ^= (tA + tB + tf->keys[2 * i + 8]) & 0xFFFFFFFF;
        D ^= (tA + 2 * tB + tf->keys[2 * i + 9]) & 0xFFFFFFFF;
        D = ROR(D, 1);

        if (i > 0) {
            UINT tmp = C;
            C = A;
            A = tmp;
            tmp = D;
            D = B;
            B = tmp;
        }
    }

    A ^= tf->keys[0];
    B ^= tf->keys[1];
    C ^= tf->keys[2];
    D ^= tf->keys[3];

    cipher[0] = (A >> 24) & 0xFF;
    cipher[1] = (A >> 16) & 0xFF;
    cipher[2] = (A >> 8) & 0xFF;
    cipher[3] = A & 0xFF;
    cipher[4] = (B >> 24) & 0xFF;
    cipher[5] = (B >> 16) & 0xFF;
    cipher[6] = (B >> 8) & 0xFF;
    cipher[7] = B & 0xFF;
    cipher[8] = (C >> 24) & 0xFF;
    cipher[9] = (C >> 16) & 0xFF;
    cipher[10] = (C >> 8) & 0xFF;
    cipher[11] = C & 0xFF;
    cipher[12] = (D >> 24) & 0xFF;
    cipher[13] = (D >> 16) & 0xFF;
    cipher[14] = (D >> 8) & 0xFF;
    cipher[15] = D & 0xFF;
    return cipher;
}

void process_directory(const char *dirpath, BYTE *key, size_t key_len, int encrypt) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char path[MAX_PATH];

    snprintf(path, MAX_PATH, "%s\\*", dirpath);

    hFind = FindFirstFile(path, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Error opening the directory: %s\n", dirpath);
        return;
    }

    do {
        if (strcmp(findFileData.cFileName, ".") == 0 || strcmp(findFileData.cFileName, "..") == 0) {
            continue;
        }

        char input_path[MAX_PATH];
        snprintf(input_path, MAX_PATH, "%s\\%s", dirpath, findFileData.cFileName);

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            printf("Processing the directory: %s\n", input_path);
            process_directory(input_path, key, key_len, encrypt);
        } else {
            printf("Processing the file: %s\n", input_path);
            process_file(input_path, key, key_len, encrypt);
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}

void process_file(const char *input_path, BYTE *key, size_t key_len, int encrypt) {
    char temp_path[MAX_PATH];
    snprintf(temp_path, MAX_PATH, "%s.temp", input_path);

    FILE *input_file = fopen(input_path, "rb");
    FILE *temp_file = fopen(temp_path, "wb");
    if (!input_file || !temp_file) {
        perror("File opening error");
        if (input_file) fclose(input_file);
        if (temp_file) fclose(temp_file);
        _unlink(temp_path);
        return;
    }

    TwoFish tf;
    TwoFish_init(&tf, key, key_len);

    BYTE buffer[BLOCK_SIZE];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE, input_file)) > 0) {
        if (encrypt) {
            if (bytes_read < BLOCK_SIZE) {
                add_padding(buffer, bytes_read, BLOCK_SIZE);
            }
            TwoFish_encrypt(&tf, buffer);
            fwrite(buffer, 1, BLOCK_SIZE, temp_file);
        } else {
            TwoFish_decrypt(&tf, buffer);
            if (feof(input_file)) {
                if (!is_valid_padding(buffer, BLOCK_SIZE)) {
                    printf("Error: Incorrect padding.\n");
                    fclose(input_file);
                    fclose(temp_file);
                    _unlink(temp_path);
                    TwoFish_cleanup(&tf);
                    return;
                }
                bytes_read = remove_padding(buffer, BLOCK_SIZE);
            }
            fwrite(buffer, 1, bytes_read, temp_file);
        }
    }

    fclose(input_file);
    fclose(temp_file);
    TwoFish_cleanup(&tf);

    if (access(input_path, F_OK) == 0 && _unlink(input_path) != 0) {
        perror("Error deleting the source file");
        _unlink(temp_path);
        return;
    }

    if (rename(temp_path, input_path) != 0) {
        perror("File replacement error");
        _unlink(temp_path);
    } else {
        printf("File '%s' successfully processed.\n", input_path);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Использование: %s <input_path> <key> <mode>\n", argv[0]);
        printf("<key>: 32-байтный ключ в hex-формате (64 символа, например: 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F)\n");
        printf("<mode>: 1 - шифрование, 0 - расшифровка\n");
        return 1;
    }

    const char *input_path = argv[1];
    const char *key_str = argv[2];
    int mode = atoi(argv[3]);

    if (strlen(key_str) != 64) {
        printf("Error: The key must contain 64 characters (32 bytes in hex format).\n");
        return 1;
    }

    BYTE key[MAX_KEY_LEN];
    parse_key(key_str, key, MAX_KEY_LEN);

    DWORD attr = GetFileAttributes(input_path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        printf("Path access error: %s\n", input_path);
        return 1;
    }

    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        process_directory(input_path, key, MAX_KEY_LEN, mode);
    } else {
        process_file(input_path, key, MAX_KEY_LEN, mode);
    }

    return 0;
}

