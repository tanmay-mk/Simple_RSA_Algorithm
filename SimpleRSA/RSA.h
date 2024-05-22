/*
 * MIT License
 *
 * Copyright (c) 2024 Tanmay Mahendra Kothale
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _RSA_H_
#define _RSA_H_

#include <stdint.h>
#include <stdbool.h>

typedef struct key {
    uint32_t mod;
    uint32_t exp;
}key_t;

extern key_t public_key;
extern key_t private_key;

bool RSA_Init(uint32_t p, uint32_t q);
void RSA_Encrypt(uint8_t *text, uint32_t textSize, uint64_t *encryptedData, key_t *key);
void RSA_Decrypt(uint8_t *text, uint32_t textSize, uint64_t *encryptedData, key_t *key);

#endif // _RSA_H_
