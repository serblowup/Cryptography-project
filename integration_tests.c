#include "main.h"
#include <assert.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <dirent.h>

// Вспомогательная функция для сравнения двух файлов
bool compare_files(const char* file1, const char* file2) {
    FILE* f1 = fopen(file1, "rb");
    FILE* f2 = fopen(file2, "rb");
    if (!f1 || !f2) return false;

    fseek(f1, 0, SEEK_END);
    fseek(f2, 0, SEEK_END);
    long size1 = ftell(f1);
    long size2 = ftell(f2);

    if (size1 != size2) {
        fclose(f1);
        fclose(f2);
        return false;
    }

    fseek(f1, 0, SEEK_SET);
    fseek(f2, 0, SEEK_SET);

    int equal = 1;
    char buf1[1024], buf2[1024];
    size_t bytes_read1, bytes_read2;

    do {
        bytes_read1 = fread(buf1, 1, sizeof(buf1), f1);
        bytes_read2 = fread(buf2, 1, sizeof(buf2), f2);

        if (bytes_read1 != bytes_read2 ||
            memcmp(buf1, buf2, bytes_read1) != 0) {
            equal = 0;
            break;
        }
    } while (bytes_read1 > 0);

    fclose(f1);
    fclose(f2);
    return equal;
}

// Тест аутентификации
void test_auth_flow() {
    BYTE key[KEY_SIZE];

    // Очистить всех существующих тестовых пользователей
    remove(USERS_FILE);

    // Тест регистрации
    FILE* input = fopen("test_input.txt", "w");
    fprintf(input, "1\ntestuser\ntestpass\n");
    fclose(input);

    freopen("test_input.txt", "r", stdin);
    int result = authenticate(key);
    assert(result == 1);

    // Тестовый вход с правильными данными
    input = fopen("test_input.txt", "w");
    fprintf(input, "2\ntestuser\ntestpass\n");
    fclose(input);

    freopen("test_input.txt", "r", stdin);
    result = authenticate(key);
    assert(result == 1);

    // Тестовый вход с неправильными данными
    input = fopen("test_input.txt", "w");
    fprintf(input, "2\ntestuser\nwrongpass\n");
    fclose(input);

    freopen("test_input.txt", "r", stdin);
    result = authenticate(key);
    assert(result == 0);

    remove("test_input.txt");
    printf("test_auth_flow: PASSED\n");
}

// Тест шифрования/дешифрования
void test_encryption_flow() {
    const char* test_file = "integration_test_file.txt";
    const char* test_content = "This is a test file for integration testing of encryption/decryption flow.";

    // Создаем тестовый файл
    FILE* f = fopen(test_file, "wb");
    fwrite(test_content, 1, strlen(test_content), f);
    fclose(f);

    // Генерируем ключ
    BYTE key[KEY_SIZE];
    generate_key_from_password("integration_test_pass", key);

    // Тест шифрования
    process_file(test_file, key, 1);

    // Файл зашифрован (содержимое должно измениться)
    f = fopen(test_file, "rb");
    char buf[128];
    fread(buf, 1, sizeof(buf), f);
    fclose(f);
    assert(memcmp(buf, test_content, strlen(test_content)) != 0);

    // Тест дешифрования
    process_file(test_file, key, 0);

    // Файл дешифрован (содержимое должно стать изначальным)
    f = fopen(test_file, "rb");
    fread(buf, 1, sizeof(buf), f);
    fclose(f);
    assert(memcmp(buf, test_content, strlen(test_content)) == 0);

    // Очистка
    remove(test_file);
    printf("test_encryption_flow: PASSED\n");
}

// Тестовая обработка каталога
void test_directory_processing() {
    const char* test_dir = "test_dir";
    const char* file1 = "test_dir/file1.txt";
    const char* file2 = "test_dir/subdir/file2.txt";

    // Создаем структуру тестового каталога
    mkdir(test_dir, 0700);
    mkdir("test_dir/subdir", 0700);

    FILE* f = fopen(file1, "wb");
    fwrite("File 1 content", 1, 14, f);
    fclose(f);

    f = fopen(file2, "wb");
    fwrite("File 2 content", 1, 14, f);
    fclose(f);

    // Генерируем ключ
    BYTE key[KEY_SIZE];
    generate_key_from_password("dir_test_pass", key);

    // Шифруем каталог
    process_directory(test_dir, key, 1);

    // Дешифруем каталог
    process_directory(test_dir, key, 0);

    // Файлы обработаны правильно
    f = fopen(file1, "rb");
    char buf[16];
    fread(buf, 1, sizeof(buf), f);
    fclose(f);
    assert(memcmp(buf, "File 1 content", 14) == 0);

    // Очистка
    remove(file1);
    remove(file2);
    rmdir("test_dir/subdir");
    rmdir(test_dir);
    printf("test_directory_processing: PASSED\n");
}

// Запуск всех интеграционных тестов
void run_integration_tests() {
    printf("Running integration tests...\n");

    test_auth_flow();
    test_encryption_flow();
    test_directory_processing();

    printf("\nAll integration tests passed successfully!\n");
}

