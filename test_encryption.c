/*
 * test_encryption.c - 加密模块测试程序
 */

#include <stdio.h>
#include <string.h>
#include "encryption.h"
#include "protocol_definitions.h"

int main() {
    printf("FEI Platform Encryption Module Test\n");
    printf("==================================\n\n");
    
    // 测试数据
    const char* test_message = "Hello, FEI Platform!";
    size_t msg_len = strlen(test_message);
    
    // 密钥和随机数
    unsigned char key[CHACHA20_POLY1305_KEY_SIZE];
    unsigned char nonce[CHACHA20_POLY1305_NONCE_SIZE];
    unsigned char aad[] = "FEI_AAD";
    size_t aad_len = strlen((char*)aad);
    
    // 输出缓冲区
    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];
    unsigned char tag[CHACHA20_POLY1305_TAG_SIZE];
    
    // 生成密钥和随机数
    generate_psk(key, CHACHA20_POLY1305_KEY_SIZE);
    generate_nonce(nonce, CHACHA20_POLY1305_NONCE_SIZE);
    
    printf("Original message: %s\n", test_message);
    printf("Message length: %zu bytes\n\n", msg_len);
    
    // 加密
    int encrypt_result = chacha20_poly1305_encrypt(
        (unsigned char*)test_message, msg_len,
        key, nonce, aad, aad_len,
        ciphertext, tag
    );
    
    if (encrypt_result == 0) {
        printf("Encryption successful!\n");
        
        // 解密
        int decrypt_result = chacha20_poly1305_decrypt(
            ciphertext, msg_len,
            key, nonce, aad, aad_len,
            tag, decrypted
        );
        
        if (decrypt_result == 0) {
            printf("Decryption successful!\n");
            decrypted[msg_len] = '\0'; // 添加字符串终止符
            printf("Decrypted message: %s\n", decrypted);
        } else {
            printf("Decryption failed!\n");
            return 1;
        }
    } else {
        printf("Encryption failed!\n");
        return 1;
    }
    
    printf("\nTest completed successfully!\n");
    
    return 0;
}