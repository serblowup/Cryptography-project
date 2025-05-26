#include "main.h"
#include <assert.h>
#include <stdbool.h>
#include <sys/stat.h>

// Вспомогательная функция для сравнения двух байтовых массивов
bool compare_bytes(const BYTE* a, const BYTE* b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// Тестовая инициализация генератора
void test_rng_initialization() {
    const char* seed = "test seed";
    init_rng(seed);
    uint32_t val1 = get_random_uint32();
    uint32_t val2 = get_random_uint32();

    // Повторная инициализация с тем же начальным значением должна дать ту же последовательность
    init_rng(seed);
    assert(get_random_uint32() == val1);
    assert(get_random_uint32() == val2);

    printf("test_rng_initialization: PASSED\n");
}

// Тестовое хеширование пароля
void test_password_hashing() {
    const char* password = "password123";
    BYTE hash1[KEY_SIZE], hash2[KEY_SIZE];

    hash_password(password, hash1);
    hash_password(password, hash2);

    // Один и тот же пароль должен создавать один и тот же хэш
    assert(compare_bytes(hash1, hash2, KEY_SIZE));

    // Разные пароли должны создавать разные хэши
    BYTE hash3[KEY_SIZE];
    hash_password("different", hash3);
    assert(!compare_bytes(hash1, hash3, KEY_SIZE));

    printf("test_password_hashing: PASSED\n");
}

// Тест шифрования/дешифрования TwoFish в режиме CBC
void test_twofish_cbc_roundtrip() {
    BYTE key[KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };

    BYTE plaintext[BLOCK_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };

    TwoFish tf;
    TwoFish_init(&tf, key, KEY_SIZE);

    // Генерируем IV
    BYTE iv[IV_SIZE];
    generate_random_iv(iv);

    // Шифрование в режиме CBC
    BYTE ciphertext[BLOCK_SIZE];
    memcpy(ciphertext, plaintext, BLOCK_SIZE);

    // XOR с IV перед шифрованием
    for (int i = 0; i < BLOCK_SIZE; i++) {
        ciphertext[i] ^= iv[i];
    }
    TwoFish_encrypt_block(&tf, ciphertext);

    // Дешифрование в режиме CBC
    BYTE decrypted[BLOCK_SIZE];
    memcpy(decrypted, ciphertext, BLOCK_SIZE);
    TwoFish_decrypt_block(&tf, decrypted);

    // XOR с IV после дешифрования
    for (int i = 0; i < BLOCK_SIZE; i++) {
        decrypted[i] ^= iv[i];
    }

    assert(compare_bytes(plaintext, decrypted, BLOCK_SIZE));

    TwoFish_cleanup(&tf);
    printf("test_twofish_cbc_roundtrip: PASSED\n");
}

// Тестовые функции заполнения
void test_padding() {
    BYTE block[BLOCK_SIZE] = {0};
    size_t data_len = 10;

    // Заполняем блок данными
    for (size_t i = 0; i < data_len; i++) {
        block[i] = (BYTE)(i + 1);  // 1, 2, 3, ..., 10
    }

    add_padding(block, data_len, BLOCK_SIZE);

    BYTE pad_value = BLOCK_SIZE - data_len;
    for (size_t i = data_len; i < BLOCK_SIZE; i++) {
        assert(block[i] == pad_value);
    }

    // Тестовая проверка заполнения
    assert(is_valid_padding(block, BLOCK_SIZE));

    // Тест недопустимого заполнения (слишком большое значение)
    block[BLOCK_SIZE-1] = BLOCK_SIZE + 1;
    assert(!is_valid_padding(block, BLOCK_SIZE));

    block[BLOCK_SIZE-1] = pad_value;

    size_t new_len = remove_padding(block, BLOCK_SIZE);
    assert(new_len == data_len);  // Should return original length

    printf("test_padding: PASSED\n");
}

// Обработка тестового файла (создаем временный тестовый файл)
void test_file_processing() {
    const char* test_filename = "test_file.txt";
    const char* test_content = "This is a test file for encryption/decryption. It needs to be exactly 48 characters long.";
    BYTE key[KEY_SIZE];
    generate_key_from_password("testpassword", key);

    FILE* f = fopen(test_filename, "wb");
    size_t content_len = strlen(test_content);
    fwrite(test_content, 1, content_len, f);
    fclose(f);

    // Шифрование файла
    process_file(test_filename, key, 1);

    // Дешифрование файла
    process_file(test_filename, key, 0);

    // Проверка содержимого
    f = fopen(test_filename, "rb");
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* content = malloc(size + 1);
    fread(content, 1, size, f);
    fclose(f);
    content[size] = '\0';

    // Сравнить содержимое
    size_t compare_len = content_len < size ? content_len : size;
    assert(memcmp(content, test_content, compare_len) == 0);

    free(content);
    remove(test_filename);

    printf("test_file_processing: PASSED\n");
}

// Тестовое создание каталога и логирование
void test_utility_functions() {
    // Тестовое создание каталога
    create_necessary_dirs();

    // Тестовое логирование
    log_operation("TEST", "testfile.txt", 1);

    // Проверка создания файла с логами
    FILE* log = fopen(LOG_FILE, "r");
    assert(log != NULL);
    fclose(log);

    printf("test_utility_functions: PASSED\n");
}

// Запуск всех тестов
void run_unit_tests() {
    printf("Running unit tests...\n");

    test_rng_initialization();
    test_password_hashing();
    test_twofish_cbc_roundtrip();
    test_padding();
    test_file_processing();
    test_utility_functions();

    printf("\nAll tests passed successfully!\n");
}
