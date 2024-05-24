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

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "RSA.h"

#define MAX_SIZE (512)

bool CheckPrimeNumber(uint32_t num)
{
    for (uint32_t i = 2; i <= (num / 2); i++)
    {
        // check if num is divisible by any number less than num/2.
        if (num % i == 0)
        {
            return false;
        }
    }
    return true;
}

int main()
{
    uint32_t p = 0, q = 0;

    printf("Enter two prime numbers (p & q) such that (p * q) > 256:\n");
    printf("Enter P = ");
    scanf("%u", &p);
    printf("Enter Q = ");
    scanf("%u", &q);

    if ((p*q <= 0xFF) || (CheckPrimeNumber(p) == false) || (CheckPrimeNumber(q) == false))
    {
        //encode any data byte-by-byte
        printf("Enter two prime numbers (p & q) such that (p * q) > 256:\n");
        return -1;
    }
    if (RSA_Init(p, q) == false)
    {
        printf("Failed to initialize RSA keys\n");
        return -1;
    }

    uint8_t Message[] = "This is a simple implementation of RSA algorithm which can "
                        "accept up to 4 digit prime numbers to generate public and "
                        "private keys, and then encrypt this message using the public "
                        "key and decrypts it using private key. It then compares the decrypted"
                        "message against this message and checks for correctness.";


    uint64_t EncryptedMsg[MAX_SIZE] = {0};
    uint8_t DecryptedMsg[MAX_SIZE] = {0};

    uint32_t MessageSize = strlen((char *)Message);

    RSA_Encrypt(&Message[0], MessageSize, &EncryptedMsg[0], &public_key);
    RSA_Decrypt(&DecryptedMsg[0], MessageSize, &EncryptedMsg[0], &private_key);

    printf("\n");

    if (memcmp(&DecryptedMsg[0], &Message[0], MessageSize) != 0)
    {
        printf("RSA Algorithm Failed!\n");
        return -1;
    }

    printf("RSA Algorithm Passed!\n");
    return 0;
}
