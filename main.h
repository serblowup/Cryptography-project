#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <locale.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#define BLOCK_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE BLOCK_SIZE
#define MAX_USERNAME_LEN 10
#define MAX_PASSWORD_LEN 10
#define USERS_FILE "/home/sergey/eclipse-workspace/Project_cryptography/users/users.dat"
#define LOG_FILE "/home/sergey/eclipse-workspace/Project_cryptography/logs/log.txt"
#define MAX_PATH_LEN 1024
#define PROGRESS_BAR_THRESHOLD (256 * 1024 * 1024)

typedef unsigned char BYTE;
typedef unsigned int UINT;

typedef struct {
    char username[MAX_USERNAME_LEN];
    BYTE password_hash[KEY_SIZE];
} User;

typedef struct {
    UINT keys[40];
    UINT *SBox;
    int k;
} TwoFish;

// Генератор ключей
void init_rng(const char* seed);
uint32_t get_random_uint32();
void hash_password(const char* password, BYTE* hash);
void generate_key_from_password(const char* password, BYTE* key);
void generate_random_iv(BYTE* iv);

// Аутентификация
int authenticate(BYTE* key);
void secure_zero_memory(void *ptr, size_t len);

// Шифрование
void process_file(const char *input_path, BYTE *key, int encrypt);
void process_directory(const char *dirpath, BYTE *key, int encrypt);

// TwoFish
void TwoFish_init(TwoFish *tf, BYTE *key, size_t length);
void TwoFish_cleanup(TwoFish *tf);
void TwoFish_encrypt_block(TwoFish *tf, BYTE *plain);
void TwoFish_decrypt_block(TwoFish *tf, BYTE *cipher);

// Утилиты
void log_operation(const char *operation, const char *filename, int success);
void create_necessary_dirs();
void show_progress_bar(uint64_t processed, uint64_t total);

// Тесты
void run_unit_tests();
void run_integration_tests();

// Паддинг
void add_padding(BYTE* block, size_t data_len, size_t block_size);
int is_valid_padding(BYTE* block, size_t block_size);
size_t remove_padding(BYTE* block, size_t block_size);

#endif
