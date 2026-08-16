/*
 * encryption.h - FEI平台加密模块头文件
 * 定义ChaCha20-Poly1305加密算法接口
 */

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_POLY1305_KEY_SIZE 32
#define CHACHA20_POLY1305_NONCE_SIZE 12
#define CHACHA20_POLY1305_TAG_SIZE 16

/**
 * 使用ChaCha20-Poly1305加密数据
 * @param plaintext 待加密的明文
 * @param plaintext_len 明文长度
 * @param key 密钥 (CHACHA20_POLY1305_KEY_SIZE 字节)
 * @param nonce 随机数 (CHACHA20_POLY1305_NONCE_SIZE 字节)
 * @param aad 附加认证数据
 * @param aad_len AAD长度
 * @param ciphertext 输出的密文
 * @param tag 认证标签 (CHACHA20_POLY1305_TAG_SIZE 字节)
 * @return 0表示成功，非0表示失败
 */
int chacha20_poly1305_encrypt(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *aad,
    size_t aad_len,
    unsigned char *ciphertext,
    unsigned char *tag
);

/**
 * 使用ChaCha20-Poly1305解密数据
 * @param ciphertext 待解密的密文
 * @param ciphertext_len 密文长度
 * @param key 密钥 (CHACHA20_POLY1305_KEY_SIZE 字节)
 * @param nonce 随机数 (CHACHA20_POLY1305_NONCE_SIZE 字节)
 * @param aad 附加认证数据
 * @param aad_len AAD长度
 * @param tag 认证标签 (CHACHA20_POLY1305_TAG_SIZE 字节)
 * @param plaintext 输出的明文
 * @return 0表示成功，非0表示失败
 */
int chacha20_poly1305_decrypt(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char *tag,
    unsigned char *plaintext
);

/**
 * 生成随机数
 * @param output 输出缓冲区
 * @param len 需要生成的随机数字节数
 * @return 0表示成功，非0表示失败
 */
int generate_nonce(unsigned char *output, size_t len);

/**
 * 生成预共享密钥(PSK)
 * @param output 输出缓冲区
 * @param len 需要生成的密钥长度
 * @return 0表示成功，非0表示失败
 */
int generate_psk(unsigned char *output, size_t len);

#endif // ENCRYPTION_H