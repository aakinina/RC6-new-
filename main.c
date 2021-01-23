#include <stdio.h>

#include "rc6.h"

int main()
{
    static char K16[] = {
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };

    pbuf(K16, sizeof(K16), "Key: ");

    printf("\n");

    size_t c;
    uint32_t *L = key_conversion(K16, sizeof(K16), &c);

    uint32_t S[S_size]; key_expansion(L, c, S);

   static char message[block_size] = {
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };

    pbuf(message, block_size, "Plaintext: ");

    printf("\n");

    uint32_t ABCD[4];
    generate_block(message, ABCD);

    rc6_encryption(S, ABCD);

    block_to_chars(ABCD, message);
    pbuf(message, block_size, "Ciphertext: ");

    printf("\n");

    rc6_decryption(S, ABCD);

    block_to_chars(ABCD, message);
    pbuf(message, block_size, "Decrypted: ");

    free(L);

    printf("\n\n\n");

    static char K24[] = {
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };

    pbuf(K24, sizeof(K24), "Key: ");

    printf("\n");

    L = key_conversion(K24, sizeof(K24), &c);

    key_expansion(L, c, S);

    pbuf(message, block_size, "Plaintext: ");

    printf("\n");

    generate_block(message, ABCD);

    rc6_encryption(S, ABCD);

    block_to_chars(ABCD, message);
    pbuf(message, block_size, "Ciphertext: ");

    printf("\n");

    rc6_decryption(S, ABCD);

    block_to_chars(ABCD, message);
    pbuf(message, block_size, "Decrypted: ");

    free(L);

    printf("\n\n\n");

    static char K32[] = {
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
    };

    pbuf(K32, sizeof(K32), "Key: ");

    printf("\n");

    L = key_conversion(K32, sizeof(K32), &c);

    key_expansion(L, c, S);

    pbuf(message, block_size, "Plaintext: ");

    printf("\n");

    generate_block(message, ABCD);

    rc6_encryption(S, ABCD);

    block_to_chars(ABCD, message);
    pbuf(message, block_size, "Ciphertext: ");

    printf("\n");

    rc6_decryption(S, ABCD);

    block_to_chars(ABCD, message);
    pbuf(message, block_size, "Decrypted: ");

    free(L);

    return 0;
}
