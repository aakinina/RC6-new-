#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

#define MAX(x,y) (((x)>(y))?(x):(y))

#define w 32

#define r 20

#define P32 0xB7E15163
#define Q32 0x9E3779B9

#define n (w/8)

#define block_size (4*n)

#define S_size (2*r + 4)

static void pbuf(const void *buf, size_t len, const void *prefix)
{
    if (prefix) printf("%s", (char *)prefix);
    for (size_t i = 0; i < len; ++i)
        printf("%02X", ((unsigned char *)buf)[i]);
    printf("\n");
}

uint32_t rotl(uint32_t x, uint32_t y)
{
    return (x << y) | (x >> (32 - y));
}

uint32_t rotr(uint32_t x, uint32_t y)
{
    return (x >> y) | (x << (32 - y));
}

uint32_t* key_conversion(const char *K, size_t b, size_t *c)
{
    *c = (MAX(b / n, 1));

    uint32_t *L = (uint32_t *)malloc((*c)*n);

    for (int i = b - 1; i >= 0 ; --i)
    {
        L[i/n] = (L[i/n] << 8) + K[i];
    }

    return L;
}

void key_expansion(uint32_t *L, size_t c, uint32_t S[S_size])
{
    S[0] = P32;
    for (int i = 1; i < S_size; ++i)
    {
        S[i] = S[i - 1] + Q32;
    }

    uint32_t A, B, i, j;
    A = B = i = j = 0;

    for (size_t _ = 0; _ < 3 * MAX(c, S_size); ++_)
    {
        A = S[i] = rotl(S[i] + A + B, 3);
        B = L[j] = rotl(L[j] + A + B, A + B);

        i = (i + 1) % S_size;
        j = (j + 1) % c;
    }
}

#define A ABCD[0]
#define B ABCD[1]
#define C ABCD[2]
#define D ABCD[3]

void generate_block(const char message[block_size], uint32_t ABCD[4])
{
    for (int i = 0; i < 4; ++i)
    {
        ABCD[i] = ((uint32_t *)message)[i];
    }
}

void block_to_chars(const uint32_t ABCD[4], char message[block_size])
{
    for (int i = block_size - 1; i >= 0 ; --i)
    {
        message[i] = ((char *)&ABCD[i/4])[i % 4];
    }
}

void rc6_encryption(const uint32_t S[S_size], uint32_t ABCD[4])
{
    uint32_t t, u;

    B += S[0];
    D += S[1];

    for (int i = 1; i <= r; ++i)
    {
        t = rotl((B * (2*B + 1)), 5);
        u = rotl((D * (2*D + 1)), 5);
        A = rotl((A ^ t), u) + S[2*i];
        C = rotl((C ^ u), t) + S[2*i + 1];

        uint32_t temp = A;
        A = B;
        B = C;
        C = D;
        D = temp;
    }
    A += S[2*r + 2];
    C += S[2*r + 3];
}

void rc6_decryption(const uint32_t S[S_size], uint32_t ABCD[4])
{
    uint32_t t, u;

    C -= S[2*r + 3];
    A -= S[2*r + 2];

    for (int i = r; i >= 1; --i)
    {
        uint32_t temp = A;
        A = D;
        D = C;
        C = B;
        B = temp;

        u = rotl((D * (2 * D + 1)), 5);
        t = rotl((B * (2 * B + 1)), 5);
        C = rotr((C - S[2*i + 1]), t) ^ u;
        A = rotr((A - S[2*i]), u) ^ t;
    }
    D -= S[1];
    B -= S[0];
}

#undef A
#undef B
#undef C
#undef D
