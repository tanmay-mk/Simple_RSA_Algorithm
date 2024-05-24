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

/*Includes*/
#include <stdint.h>
#include <stdbool.h>

/*Defines*/

/*Enums*/

/*Structs*/
//structure to hold key data
typedef struct key {
    uint32_t mod;
    uint32_t exp;
}key_t;

/*Exported global variables*/
extern key_t public_key;
extern key_t private_key;


/*
 * @brief   : Initialize RSA
 *
 * @params  : uint32_t
 *              p    : first prime number
 *              q    : second prime number
 *
 * @returns : bool
 *              true : if initialization is successful
 *              false: if initialization fails
 */
bool RSA_Init(uint32_t p, uint32_t q);

/*
 * @brief   : Encrypt a message using public/private key
 *
 * @params  : uint8_t
 *              *text           : message to encrypt
 *            uint32_t
 *              textSize        : number of bytes to encrypt
 *            uint64_t
 *              *encryptedData  : location to store encrypted message
 *            key_t
 *              *key            : key to use for encryption
 *
 * @returns : none
 */
void RSA_Encrypt(uint8_t *text, uint32_t textSize, uint64_t *encryptedData, key_t *key);

/*
 * @brief   : Decrypt a message using public/private key
 *
 * @params  : uint8_t
 *              *text           : location to store decrypted message
 *            uint32_t
 *              textSize        : number of bytes to decrypt
 *            uint64_t
 *              *encryptedData  : message to decrypt
 *            key_t
 *              *key            : key to use for decryption
 *
 * @returns : none
 */
void RSA_Decrypt(uint8_t *text, uint32_t textSize, uint64_t *encryptedData, key_t *key);

#endif // _RSA_H_
