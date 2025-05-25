#include "main.h"
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

// Глобальные переменные и константы
static uint32_t ShiftRegister = 1;

static const BYTE substitution_table[256] = {
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

// Реализация генератора случайных чисел
static int next_bit(void) {
    uint32_t new_bit = ((ShiftRegister >> 31) ^ (ShiftRegister >> 6) ^
                      (ShiftRegister >> 4) ^ (ShiftRegister >> 2) ^
                      (ShiftRegister >> 1) ^ ShiftRegister) & 0x00000001;
    ShiftRegister = (ShiftRegister >> 1) | (new_bit << 31);
    return (int)(ShiftRegister & 0x00000001);
}

void init_rng(const char* seed) {
    ShiftRegister = 0;
    for (size_t i = 0; seed[i] != '\0'; i++) {
        ShiftRegister = (ShiftRegister << 5) + ShiftRegister + seed[i];
    }
    if (ShiftRegister == 0) ShiftRegister = 1;
}

uint32_t get_random_uint32() {
    uint32_t result = 0;
    for (int i = 0; i < 32; i++) {
        result = (result << 1) | next_bit();
    }
    return result;
}

// Функции хеширования и генерации ключа
void hash_password(const char* password, BYTE* hash) {
    init_rng(password);

    for (size_t i = 0; i < KEY_SIZE; i += 4) {
        uint32_t rand_val = get_random_uint32();
        for (int j = 0; j < 4 && (i + j) < KEY_SIZE; j++) {
            hash[i + j] = (rand_val >> (8 * j)) & 0xFF;
        }
    }

    for (size_t i = 0; i < KEY_SIZE; i++) {
        hash[i] = substitution_table[hash[i]];
        if (i > 0) hash[i] ^= hash[i-1];
    }
}

void generate_key_from_password(const char* password, BYTE* key) {
    hash_password(password, key);
}

// Функции аутентификации
int authenticate(BYTE* key) {
    char username[MAX_USERNAME_LEN + 2];
    char password[MAX_PASSWORD_LEN + 2];
    User user;
    FILE* users_file;

    printf(" Authentication \n");
    printf("1. Registration\n2. Login\n> ");
    int choice;
    if (scanf("%d", &choice) != 1 || (choice != 1 && choice != 2)) {
        printf("Invalid choice!\n");
        while (getchar() != '\n');
        return 0;
    }
    while (getchar() != '\n');

    printf("Username (max %d chars): ", MAX_USERNAME_LEN);
    if (!fgets(username, sizeof(username), stdin)) return 0;
    username[strcspn(username, "\n")] = '\0';

    if (strlen(username) == 0 || strlen(username) > MAX_USERNAME_LEN) {
        printf("Invalid username length!\n");
        return 0;
    }

    printf("Password (max %d chars): ", MAX_PASSWORD_LEN);
    if (!fgets(password, sizeof(password), stdin)) return 0;
    password[strcspn(password, "\n")] = '\0';

    if (strlen(password) == 0 || strlen(password) > MAX_PASSWORD_LEN) {
        printf("Invalid password length!\n");
        secure_zero_memory(password, MAX_PASSWORD_LEN);
        return 0;
    }

    // Генерируем хеш пароля (256-битный ключ)
    generate_key_from_password(password, key);
    secure_zero_memory(password, MAX_PASSWORD_LEN);

    users_file = fopen(USERS_FILE, choice == 1 ? "ab+" : "rb");
    if (!users_file) {
        log_operation("AUTH", "Failed to open users file", 0);
        return 0;
    }

    // Регистрация
    if (choice == 1) {
        while (fread(&user, sizeof(User), 1, users_file)) {
            if (strcmp(user.username, username) == 0) {
                fclose(users_file);
                printf("User already exists!\n");
                log_operation("REGISTER", username, 0);
                return 0;
            }
        }
        strncpy(user.username, username, MAX_USERNAME_LEN);
        memcpy(user.password_hash, key, KEY_SIZE);
        fwrite(&user, sizeof(User), 1, users_file);
        printf("Registration successful!\n");
        log_operation("REGISTER", username, 1);
    }
    // Вход
    else {
        int found = 0;
        while (fread(&user, sizeof(User), 1, users_file)) {
            if (strcmp(user.username, username) == 0) {
                if (memcmp(user.password_hash, key, KEY_SIZE) == 0) {
                    found = 1;
                    break;
                }
            }
        }

        if (!found) {
            printf("Invalid credentials!\n");
            log_operation("LOGIN", username, 0);
            fclose(users_file);
            return 0;
        }
        printf("Login successful!\n");
        log_operation("LOGIN", username, 1);
    }

    fclose(users_file);
    return 1;
}

// Реализация TwoFish
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

unsigned long long h(UINT x, UINT* keys, int k) {
    unsigned long long result = x;
    for (int i = 0; i < k; i++) {
        result ^= (keys[i] + result);
    }
    return result;
}

void TwoFish_init(TwoFish* tf, BYTE* key, size_t length) {
    short N = length <= 16 ? 128 : (length <= 24 ? 192 : 256);
    BYTE* temp_key = (BYTE*)malloc(N / 8);
    if (!temp_key) return;

    for (int i = 0; i < N / 8; i++) {
        temp_key[i] = (i < length) ? key[i] : 0;
    }

    tf->k = N / 64;
    UINT* Me = (UINT*)malloc(tf->k * sizeof(UINT));
    UINT* Mo = (UINT*)malloc(tf->k * sizeof(UINT));
    if (!Me || !Mo) {
        free(temp_key); free(Me); free(Mo);
        return;
    }

    BYTE RS[4][8] = {
        {0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E},
        {0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5},
        {0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19},
        {0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03}
    };

    for (int i = 0; i < 2 * tf->k; i++) {
        UINT val = 0;
        for (int j = 0; j < 4; j++) {
            val |= (temp_key[4 * i + j] << (24 - 8 * j));
        }
        (i % 2 == 0) ? (Me[i/2] = val) : (Mo[i/2] = val);
    }

    tf->SBox = (UINT*)malloc(tf->k * sizeof(UINT));
    if (!tf->SBox) {
        free(Me); free(Mo); free(temp_key);
        return;
    }

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

    free(Me); free(Mo); free(temp_key);
}

void TwoFish_cleanup(TwoFish* tf) {
    if (tf->SBox) free(tf->SBox);
}

BYTE* TwoFish_encrypt(TwoFish* tf, BYTE* plain) {
    UINT A = (plain[0] << 24) | (plain[1] << 16) | (plain[2] << 8) | plain[3];
    UINT B = (plain[4] << 24) | (plain[5] << 16) | (plain[6] << 8) | plain[7];
    UINT C = (plain[8] << 24) | (plain[9] << 16) | (plain[10] << 8) | plain[11];
    UINT D = (plain[12] << 24) | (plain[13] << 16) | (plain[14] << 8) | plain[15];

    A ^= tf->keys[0]; B ^= tf->keys[1]; C ^= tf->keys[2]; D ^= tf->keys[3];

    for (int i = 0; i < 16; i++) {
        unsigned long long tA = h(A, tf->SBox, tf->k);
        unsigned long long tB = h(ROL(B, 8), tf->SBox, tf->k);

        D = ROL(D, 1);
        C ^= (tA + tB + tf->keys[2 * i + 8]) & 0xFFFFFFFF;
        D ^= (tA + 2 * tB + tf->keys[2 * i + 9]) & 0xFFFFFFFF;
        C = ROR(C, 1);

        if (i != 15) {
            UINT tmp = C; C = A; A = tmp;
            tmp = D; D = B; B = tmp;
        }
    }

    A ^= tf->keys[4]; B ^= tf->keys[5]; C ^= tf->keys[6]; D ^= tf->keys[7];

    for (int i = 0; i < 4; i++) {
        plain[i] = (A >> (24 - 8 * i)) & 0xFF;
        plain[i + 4] = (B >> (24 - 8 * i)) & 0xFF;
        plain[i + 8] = (C >> (24 - 8 * i)) & 0xFF;
        plain[i + 12] = (D >> (24 - 8 * i)) & 0xFF;
    }
    return plain;
}

BYTE* TwoFish_decrypt(TwoFish* tf, BYTE* cipher) {
    UINT A = (cipher[0] << 24) | (cipher[1] << 16) | (cipher[2] << 8) | cipher[3];
    UINT B = (cipher[4] << 24) | (cipher[5] << 16) | (cipher[6] << 8) | cipher[7];
    UINT C = (cipher[8] << 24) | (cipher[9] << 16) | (cipher[10] << 8) | cipher[11];
    UINT D = (cipher[12] << 24) | (cipher[13] << 16) | (cipher[14] << 8) | cipher[15];

    A ^= tf->keys[4]; B ^= tf->keys[5]; C ^= tf->keys[6]; D ^= tf->keys[7];

    for (int i = 15; i >= 0; i--) {
        unsigned long long tA = h(A, tf->SBox, tf->k);
        unsigned long long tB = h(ROL(B, 8), tf->SBox, tf->k);

        C = ROL(C, 1);
        C ^= (tA + tB + tf->keys[2 * i + 8]) & 0xFFFFFFFF;
        D ^= (tA + 2 * tB + tf->keys[2 * i + 9]) & 0xFFFFFFFF;
        D = ROR(D, 1);

        if (i > 0) {
            UINT tmp = C; C = A; A = tmp;
            tmp = D; D = B; B = tmp;
        }
    }

    A ^= tf->keys[0]; B ^= tf->keys[1]; C ^= tf->keys[2]; D ^= tf->keys[3];

    for (int i = 0; i < 4; i++) {
        cipher[i] = (A >> (24 - 8 * i)) & 0xFF;
        cipher[i + 4] = (B >> (24 - 8 * i)) & 0xFF;
        cipher[i + 8] = (C >> (24 - 8 * i)) & 0xFF;
        cipher[i + 12] = (D >> (24 - 8 * i)) & 0xFF;
    }
    return cipher;
}

// Функции работы с файлами
void add_padding(BYTE* block, size_t data_len, size_t block_size) {
    BYTE pad_value = block_size - data_len;
    for (size_t i = data_len; i < block_size; i++) {
        block[i] = pad_value;
    }
}

int is_valid_padding(BYTE* block, size_t block_size) {
    BYTE pad_value = block[block_size - 1];
    if (pad_value > block_size || pad_value == 0) return 0;
    for (size_t i = block_size - pad_value; i < block_size; i++) {
        if (block[i] != pad_value) return 0;
    }
    return 1;
}

size_t remove_padding(BYTE* block, size_t block_size) {
    BYTE pad_value = block[block_size - 1];
    return block_size - pad_value;
}

void process_file(const char* input_path, BYTE* key, int encrypt) {
    char temp_path[MAX_PATH_LEN];
    snprintf(temp_path, MAX_PATH_LEN, "%s.temp", input_path);

    FILE* input_file = fopen(input_path, "rb");
    if (!input_file) {
        printf("Error opening input file: %s\n", input_path);
        log_operation("FILE OPEN", input_path, 0);
        return;
    }

    fseek(input_file, 0, SEEK_END);
    uint64_t file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    FILE* temp_file = fopen(temp_path, "wb");
    if (!temp_file) {
        fclose(input_file);
        printf("Error creating temp file: %s\n", temp_path);
        log_operation("TEMP FILE", temp_path, 0);
        return;
    }

    TwoFish tf;
    TwoFish_init(&tf, key, KEY_SIZE);
    BYTE buffer[BLOCK_SIZE];
    size_t bytes_read;
    int success = 1;
    uint64_t total_bytes_processed = 0;
    clock_t start_time = clock();
    int show_progress = file_size >= PROGRESS_BAR_THRESHOLD;

    if (show_progress) {
        printf("Processing large file (%lld bytes)...\n", (long long)file_size);
    }

    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE, input_file)) > 0) {
        if (encrypt) {
            if (bytes_read < BLOCK_SIZE) add_padding(buffer, bytes_read, BLOCK_SIZE);
            TwoFish_encrypt(&tf, buffer);
            fwrite(buffer, 1, BLOCK_SIZE, temp_file);
        } else {
            TwoFish_decrypt(&tf, buffer);
            if (feof(input_file)) {
                if (!is_valid_padding(buffer, BLOCK_SIZE)) {
                    printf("Invalid padding in file %s!\n", input_path);
                    success = 0;
                    break;
                }
                bytes_read = remove_padding(buffer, BLOCK_SIZE);
            }
            fwrite(buffer, 1, bytes_read, temp_file);
        }
        total_bytes_processed += bytes_read;

        if (show_progress) {
            show_progress_bar(total_bytes_processed, file_size);
        }
    }

    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    fclose(input_file);
    fclose(temp_file);
    TwoFish_cleanup(&tf);

    if (!success) {
        remove(temp_path);
        log_operation("FILE PROCESS", input_path, 0);
        return;
    }

    if (remove(input_path)) {
        printf("Error deleting original file: %s\n", input_path);
        remove(temp_path);
        return;
    }

    if (rename(temp_path, input_path)) {
        printf("Error renaming temp file: %s\n", temp_path);
        remove(temp_path);
        return;
    }

    log_operation(encrypt ? "ENCRYPT" : "DECRYPT", input_path, 1);

    double file_size_mb = (double)file_size / (1024.0 * 1024.0);
    printf("\nFile %s successfully %s!\n", input_path, encrypt ? "encrypted" : "decrypted");
    printf("File size: %.2f MB\n", file_size_mb);

    if (elapsed_time > 0) {
        double speed_mb_per_sec = file_size_mb / elapsed_time;
        double speed_mbps = speed_mb_per_sec * 8;
        printf("Processing time: %.3f seconds\n", elapsed_time);
        printf("Speed: %.2f MB/s (%.2f Mbps)\n", speed_mb_per_sec, speed_mbps);
    } else {
        printf("Processing time: <1ms\n");
    }
}

void process_directory(const char* dirpath, BYTE* key, int encrypt) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;

    if ((dir = opendir(dirpath)) == NULL) {
        printf("Error opening directory: %s\n", dirpath);
        log_operation("DIR OPEN", dirpath, 0);
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[MAX_PATH_LEN];
        snprintf(full_path, MAX_PATH_LEN, "%s/%s", dirpath, entry->d_name);

        if (stat(full_path, &statbuf) == -1) {
            continue;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            process_directory(full_path, key, encrypt);
        } else {
            process_file(full_path, key, encrypt);
        }
    }

    closedir(dir);
    log_operation("DIR PROCESS", dirpath, 1);
    printf("Directory %s processed!\n", dirpath);
}

// Вспомогательные функции
void create_necessary_dirs() {
    mkdir("/home/sergey/eclipse-workspace/Project_cryptography/", 0700);
    mkdir("/home/sergey/eclipse-workspace/Project_cryptography/users", 0700);
    mkdir("/home/sergey/eclipse-workspace/Project_cryptography/logs", 0700);
}

void secure_zero_memory(void* ptr, size_t len) {
    volatile char* vptr = (volatile char*)ptr;
    while (len--) *vptr++ = 0;
}

void log_operation(const char* operation, const char* filename, int success) {
    FILE* log_file = fopen(LOG_FILE, "a");
    if (!log_file) return;

    time_t now = time(NULL);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log_file, "[%s] %s: %s - %s\n",
            time_str,
            operation,
            filename,
            success ? "SUCCESS" : "FAILED");
    fclose(log_file);
}

void show_progress_bar(uint64_t processed, uint64_t total) {
    static int initialized = 0;
    static clock_t last_update = 0;
    static int last_percent = -1;

    if (!initialized) {
        printf("\nProgress:\n");
        printf("[");
        for (int i = 0; i < 50; i++) printf(" ");
        printf("] 0%%");
        initialized = 1;
    }

    clock_t now = clock();
    if (now - last_update < CLOCKS_PER_SEC / 10 && processed != total) {
        return;
    }
    last_update = now;

    int percent = (int)((double)processed / total * 100);
    if (percent == last_percent) return;
    last_percent = percent;

    printf("\r[");
    int pos = percent / 2;
    for (int i = 0; i < 50; i++) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %d%%", percent);
    fflush(stdout);

    if (processed == total) {
        printf("\n");
        initialized = 0;
    }
}

// Главная функция
int main(int argc, char *argv[]) {
    setlocale(LC_ALL, "");

    // Check if we're running tests
    if (argc > 1) {
        if (strcmp(argv[1], "--test") == 0) {
            run_unit_tests();
            return 0;
        } else if (strcmp(argv[1], "--integration-test") == 0) {
            run_integration_tests();
            return 0;
        }
    }

    create_necessary_dirs();
    BYTE key[KEY_SIZE];
    char path[MAX_PATH_LEN];
    int mode;

    if (!authenticate(key)) {
        printf("Access denied.\n");
        return 1;
    }

    printf("Enter file/directory path: ");
    if (!fgets(path, MAX_PATH_LEN, stdin)) return 1;
    path[strcspn(path, "\n")] = '\0';

    if (path[0] == '"' && path[strlen(path)-1] == '"') {
        path[strlen(path)-1] = '\0';
        memmove(path, path+1, strlen(path));
    }

    printf("Mode (1-encrypt, 0-decrypt): ");
    if (scanf("%d", &mode) != 1 || (mode != 0 && mode != 1)) {
        printf("Invalid mode!\n");
        secure_zero_memory(key, KEY_SIZE);
        return 1;
    }

    struct stat statbuf;
    if (stat(path, &statbuf) == -1) {
        printf("Path not found: %s\n", path);
        log_operation("PATH ACCESS", path, 0);
        secure_zero_memory(key, KEY_SIZE);
        return 1;
    }

    if (S_ISDIR(statbuf.st_mode)) {
        process_directory(path, key, mode);
    } else {
        process_file(path, key, mode);
    }

    secure_zero_memory(key, KEY_SIZE);
    return 0;
}

