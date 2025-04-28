/*
 * main.h
 *
 *  Created on: 15 апр. 2025 г.
 *      Author: СЕРГЕЙ
 */

#ifndef MAIN_H_
#define MAIN_H_

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <windows.h>
#include <io.h>
#include <direct.h>

typedef unsigned int UINT;
typedef unsigned char BYTE;

typedef struct {
    UINT keys[40];
    short k;
    UINT *SBox;
} TwoFish;

void TwoFish_init(TwoFish *tf, BYTE *key, size_t length);
void TwoFish_cleanup(TwoFish *tf);
BYTE* TwoFish_encrypt(TwoFish *tf, BYTE *plain);
BYTE* TwoFish_decrypt(TwoFish *tf, BYTE *cipher);
void TwoFish_printSubkeys(TwoFish *tf);
void process_file(const char *input_path, BYTE *key, size_t key_len, int encrypt);
void process_directory(const char *dirpath, BYTE *key, size_t key_len, int encrypt);

#endif /* MAIN_H_ */




