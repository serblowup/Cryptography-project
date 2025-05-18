#ifndef MAIN_H
#define MAIN_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <direct.h>
#include <locale.h>
#include <io.h>

#define BLOCK_SIZE 16
#define MAX_KEY_LEN 32
#define MAX_USERNAME_LEN 10
#define MAX_PASSWORD_LEN 10
#define USERS_FILE "C:\\Eclipse_dev\\Project_cryptography\\users\\users.dat"
#define LOG_FILE "C:\\Eclipse_dev\\Project_cryptography\\logs\\log.txt"
#define MAX_PATH_LEN 1024

typedef unsigned char BYTE;
typedef unsigned int UINT;

typedef struct {
    char username[MAX_USERNAME_LEN];
    BYTE password_hash[MAX_KEY_LEN];
} User;

typedef struct {
    UINT keys[40];
    UINT *SBox;
    int k;
} TwoFish;

// Аутентификация
int authenticate(BYTE *key);
void secure_zero_memory(void *ptr, size_t len);

// Шифрование
void generate_key_from_password(const char *password, BYTE *key, size_t key_len);
void process_file(const char *input_path, BYTE *key, int encrypt);
void process_directory(const char *dirpath, BYTE *key, int encrypt);

// TwoFish
void TwoFish_init(TwoFish *tf, BYTE *key, size_t length);
void TwoFish_cleanup(TwoFish *tf);
BYTE* TwoFish_encrypt(TwoFish *tf, BYTE *plain);
BYTE* TwoFish_decrypt(TwoFish *tf, BYTE *cipher);

// Утилиты
void log_operation(const char *operation, const char *filename, int success);
void create_necessary_dirs();

#endif
