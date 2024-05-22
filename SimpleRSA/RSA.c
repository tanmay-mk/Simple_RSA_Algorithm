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

#include "RSA.h"

#define RSA_DEBUG

typedef struct {
    uint32_t p;
    uint32_t q;
    uint32_t n;
    uint32_t phi_n;
}RSA_t;

RSA_t RSA = {
    .p      = 0,
    .q      = 0,
    .n      = 0,
    .phi_n  = 0
};

key_t public_key;
key_t private_key;

static uint32_t GCD(uint32_t num1, uint32_t num2)
{
    uint32_t gcd = ((num1 < num2)? num1 : num2);

    while (gcd > 0)
    {
        if (((num1 % gcd) == 0) && ((num2 % gcd) == 0))
        {
            break;
        }
        gcd--;
    }
    return gcd;
}

static bool GenerateKeys(uint32_t p, uint32_t q)
{
    RSA.p       = p;
    RSA.q       = q;
    RSA.n       = (p*q);
    RSA.phi_n   = ((p-1) * (q-1));

    //find 'e' such that
    //1. 1 < e < phi(n)
    //2. gcd (e, phi(n)) == 1
    uint32_t e = 2;
    while(GCD(e, RSA.phi_n) != 1)
    {
        e++;
        if (e >= RSA.phi_n)
        {
            return false;
        }
    }

    //find 'd' such that
    //((e*d) % n) == 1
    uint32_t d = 0;
    while (((d*e) % RSA.phi_n) != 1)
    {
        d++;
    }

    //populate keys
    public_key.mod = RSA.n;
    public_key.exp = e;

    private_key.mod = RSA.n;
    private_key.exp = d;

    //printf("p = %u, q = %u, n = %u, phi_n = %u, e = %u, d = %u\n\n",
    //       RSA.p, RSA.q, RSA.n, RSA.phi_n, e, d);

    return true;
}

static uint64_t Encrypt(uint8_t m, key_t *key)
{
    uint32_t n = key->mod, e = key->exp;

    uint64_t c = 1;

    while (e > 0)
    {
        c = (c * m);
        c = (c % n);
        e--;
    }

    //printf("m = %u, e = %u, n = %u, c = %u\n", m, key->exp, n, c);

    return c;
}

static uint8_t Decrypt(uint32_t c, key_t *key)
{
    uint32_t n = key->mod, d = key->exp;

    uint64_t m = 1;

    while (d > 0)
    {
        m = (m * c);
        m = (m % n);
        d--;
    }

    //printf("c = %u, d = %u, n = %u, m = %u\n", c, key->exp, n, m);

    return ((uint8_t)m);
}

void RSA_Encrypt(uint8_t *text, uint32_t textSize, uint64_t *encryptedData, key_t *key)
{
    for (uint32_t i=0; i<textSize; i++)
    {
        encryptedData[i] = Encrypt(text[i], key);
    }
}

void RSA_Decrypt(uint8_t *text, uint32_t textSize, uint64_t *encryptedData, key_t *key)
{
    for (uint32_t i=0; i<textSize; i++)
    {
        text[i] = Decrypt(encryptedData[i], key);
    }
}

bool RSA_Init(uint32_t p, uint32_t q)
{
    return (GenerateKeys(p, q));
}
