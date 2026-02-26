#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
# error "Little endian byte order required."
#endif

#include "md5.h"
#include <string.h>

void MD5_Init(MD5_CTX* const context)
{
    if (context == NULL)
        return;

    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;

    context->bytesInUse = 0;
    context->totalBits = 0;
    memset(context->buffer.bytes, 0, 64);
}

static void MD5_Block(uint32_t[4], const uint32_t[16]);

void MD5_Update(MD5_CTX* const context, const void* const data, size_t length)
{
    if (context == NULL || data == NULL || length == 0)
        return;

    context->totalBits += length << 3;

    if (context->bytesInUse > 64)
        context->bytesInUse = 64;

    size_t bytesProcessed = 0;

    if (context->bytesInUse != 0) {
        size_t remainingBytes = 64 - context->bytesInUse;
        size_t toCopy = (length < remainingBytes) ? length : remainingBytes;

        memcpy(context->buffer.bytes + context->bytesInUse, data, toCopy);
        context->bytesInUse += toCopy;
        bytesProcessed += toCopy;

        if (context->bytesInUse == 64) {
            MD5_Block(context->state, context->buffer.words);
            context->bytesInUse = 0;
        }
    }

    while (bytesProcessed + 64 <= length) {
        MD5_Block(context->state, data+bytesProcessed);
        bytesProcessed += 64;
    }

    if (bytesProcessed < length) {
        size_t unprocessedBytes = length - bytesProcessed;
        memcpy(context->buffer.bytes, data+bytesProcessed, unprocessedBytes);
        context->bytesInUse = unprocessedBytes;
    }
}

void MD5_Final(uint8_t digest[16], MD5_CTX* const context)
{
    if (context == NULL || digest == NULL)
        return;

    // Something is seriously wrong if this executes
    if (context->bytesInUse >= 64) {
        MD5_Block(context->state, context->buffer.words);
        context->bytesInUse = 0;
    }

    // Mark the end of the data
    context->buffer.bytes[context->bytesInUse++] = 0x80;

    if (context->bytesInUse > 56) {
        memset(context->buffer.bytes + context->bytesInUse, 0, 64 - context->bytesInUse);
        MD5_Block(context->state, context->buffer.words);
        context->bytesInUse = 0;
    }

    // Pad out with zeros, last 8 bytes are for total bits used
    memset(context->buffer.bytes + context->bytesInUse, 0, 56 - context->bytesInUse);

    context->buffer.words[14] = (uint32_t)(context->totalBits & 0xFFFFFFFF);
    context->buffer.words[15] = (uint32_t)(context->totalBits >> 32);

    MD5_Block(context->state, context->buffer.words);

    memcpy(digest, context->state, 16);
}

#if defined(__x86_64__) || defined(__amd64__)
// This code is an adaptation of the NoLEA-G implementation
// https://github.com/animetosho/md5-optimisation

#ifndef STR
# define STR_HELPER(x) #x
# define STR(x) STR_HELPER(x)
#endif

#define INPUT_ARRAY [input0]"m"(input[0]), [input1]"m"(input[1]), [input2]"m"(input[2]), [input3]"m"(input[3]), [input4]"m"(input[4]), [input5]"m"(input[5]), [input6]"m"(input[6]), [input7]"m"(input[7]), [input8]"m"(input[8]), [input9]"m"(input[9]), [input10]"m"(input[10]), [input11]"m"(input[11]), [input12]"m"(input[12]), [input13]"m"(input[13]), [input14]"m"(input[14]), [input15]"m"(input[15])

#define ROUND_F(I, A, B, C, D, NEXT_IN, K, R) \
    "xorl %k[" STR(C) "], %k[TMP1]\n" \
    "leal " STR(K) "(%k[" STR(I) STR(A) "], %k[TMP2]), %k[" STR(A) "]\n" \
    "andl %k[" STR(B) "], %k[TMP1]\n" \
    "movl " NEXT_IN ", %k[TMP2]\n" \
    "xorl %k[" STR(D) "], %k[TMP1]\n" \
    "addl %k[TMP1], %k[" STR(A) "]\n" \
    "roll $" STR(R) ", %k[" STR(A) "]\n" \
    "movl %k[" STR(C) "], %k[TMP1]\n" \
    "addl %k[" STR(B) "], %k[" STR(A) "]\n"

#define RF4(I, i0, i1, i2, i3, k0, k1, k2, k3) \
    ROUND_F(I, A, I##B, I##C, I##D, "%[input" STR(i0) "]", k0, 7) \
    ROUND_F(I, D, A, I##B, I##C, "%[input" STR(i1) "]", k1, 12) \
    ROUND_F(I, C, D, A, I##B, "%[input" STR(i2) "]", k2, 17) \
    ROUND_F(I, B, C, D, A, "%[input" STR(i3) "]", k3, 22)

#define ROUND_G(A, B, C, D, NEXT_IN, K, R) \
    "notl %k[TMP1]\n" \
    "addl $" STR(K) ", %k[" STR(A) "]\n" \
    "andl %k[" STR(C) "], %k[TMP1]\n" \
    "movl %k[" STR(D) "], %k[TMP2]\n" \
    "addl " NEXT_IN ", %k[" STR(D) "]\n" \
    "addl %k[TMP1], %k[" STR(A) "]\n" \
    "andl %k[" STR(B) "], %k[TMP2]\n" \
    "addl %k[TMP2], %k[" STR(A) "]\n" \
    "roll $" STR(R) ", %k[" STR(A) "]\n" \
    "movl %k[" STR(C) "], %k[TMP1]\n" \
    "addl %k[" STR(B) "], %k[" STR(A) "]\n"

#define RG4(i0, i1, i2, i3, k0, k1, k2, k3) \
    ROUND_G(A, B, C, D, "%[input" STR(i0) "]", k0, 5) \
    ROUND_G(D, A, B, C, "%[input" STR(i1) "]", k1, 9) \
    ROUND_G(C, D, A, B, "%[input" STR(i2) "]", k2, 14) \
    ROUND_G(B, C, D, A, "%[input" STR(i3) "]", k3, 20)

#define ROUND_H(A, B, C, D, NEXT_IN, K, R) \
    "xorl %k[" STR(C) "], %k[TMP1]\n" \
    "leal " STR(K) "(%k[" STR(A) "], %k[TMP2]), %k[" STR(A) "]\n" \
    "xorl %k[" STR(B) "], %k[TMP1]\n" \
    "movl " NEXT_IN ", %k[TMP2]\n" \
    "addl %k[TMP1], %k[" STR(A) "]\n" \
    "roll $" STR(R) ", %k[" STR(A) "]\n" \
    "movl %k[" STR(C) "], %k[TMP1]\n" \
    "addl %k[" STR(B) "], %k[" STR(A) "]\n"

#define RH4(i0, i1, i2, i3, k0, k1, k2, k3) \
    ROUND_H(A, B, C, D, "%[input" STR(i0) "]", k0, 4) \
    ROUND_H(D, A, B, C, "%[input" STR(i1) "]", k1, 11) \
    ROUND_H(C, D, A, B, "%[input" STR(i2) "]", k2, 16) \
    ROUND_H(B, C, D, A, "%[input" STR(i3) "]", k3, 23)

#define ROUND_I(A, B, C, D, NEXT_IN, K, R) \
    "notl %k[TMP1]\n" \
    "leal " STR(K) "(%k[" STR(A) "], %k[TMP2]), %k[" STR(A) "]\n" \
    "orl %k[" STR(B) "], %k[TMP1]\n" \
    "movl " NEXT_IN ", %k[TMP2]\n" \
    "xorl %k[" STR(C) "], %k[TMP1]\n" \
    "addl %k[TMP1], %k[" STR(A) "]\n" \
    "roll $" STR(R) ", %k[" STR(A) "]\n" \
    "movl %k[" STR(C) "], %k[TMP1]\n" \
    "addl %k[" STR(B) "], %k[" STR(A) "]\n"

#define ROUND_I_LAST(A, B, C, D, K, R) \
    "notl %k[TMP1]\n" \
    "leal " STR(K) "(%k[" STR(A) "], %k[TMP2]), %k[" STR(A) "]\n" \
    "orl %k[" STR(B) "], %k[TMP1]\n" \
    "xorl %k[" STR(C) "], %k[TMP1]\n" \
    "addl %k[TMP1], %k[" STR(A) "]\n" \
    "roll $" STR(R) ", %k[" STR(A) "]\n" \
    "addl %k[" STR(B) "], %k[" STR(A) "]\n"

#define RI4(i0, i1, i2, i3, k0, k1, k2, k3) \
    ROUND_I(A, B, C, D, "%[input" STR(i0) "]", k0, 6) \
    ROUND_I(D, A, B, C, "%[input" STR(i1) "]", k1, 10) \
    ROUND_I(C, D, A, B, "%[input" STR(i2) "]", k2, 15) \
    ROUND_I(B, C, D, A, "%[input" STR(i3) "]", k3, 21)

static void MD5_Block(uint32_t state[4], const uint32_t input[16])
{
    if (state == NULL || input == NULL)
        return;

    uint32_t A = state[0];
    uint32_t B = state[1];
    uint32_t C = state[2];
    uint32_t D = state[3];

    void *tmp1, *tmp2;

    __asm__(
        "addl %[input0], %k[A]\n"
        "movl %k[D], %k[TMP1]\n"
        RF4(,  1,  2,  3,  4,  -0x28955b88, -0x173848aa, 0x242070db, -0x3e423112)
        RF4(,  5,  6,  7,  8,  -0x0a83f051, 0x4787c62a, -0x57cfb9ed, -0x02b96aff)
        RF4(,  9, 10, 11, 12,  0x698098d8, -0x74bb0851, -0x0000a44f, -0x76a32842)
        RF4(, 13, 14, 15,  1,  0x6b901122, -0x02678e6d, -0x5986bc72, 0x49b40821)
    : [TMP1]"=&R"(tmp1), [TMP2]"=&r"(tmp2),
      [A]"+&R"(A), [B]"+&R"(B), [C]"+&R"(C), [D]"+&R"(D)
    : INPUT_ARRAY
    :);

    __asm__(
        RG4( 6, 11,  0,  5,  -0x09e1da9e, -0x3fbf4cc0, 0x265e5a51, -0x16493856)
        RG4(10, 15,  4,  9,  -0x29d0efa3, 0x02441453, -0x275e197f, -0x182c0438)
        RG4(14,  3,  8, 13,  0x21e1cde6, -0x3cc8f82a, -0x0b2af279, 0x455a14ed)
        RG4( 2,  7, 12,  5,  -0x561c16fb, -0x03105c08, 0x676f02d9, -0x72d5b376)

        RH4( 8, 11, 14,  1,  -0x0005c6be, -0x788e097f, 0x6d9d6122, -0x021ac7f4)
        RH4( 4,  7, 10, 13,  -0x5b4115bc, 0x4bdecfa9, -0x0944b4a0, -0x41404390)
        RH4( 0,  3,  6,  9,  0x289b7ec6, -0x155ed806, -0x2b10cf7b, 0x04881d05)
        RH4(12, 15,  2,  0,  -0x262b2fc7, -0x1924661b, 0x1fa27cf8, -0x3b53a99b)

        RI4( 7, 14,  5, 12,  -0x0bd6ddbc, 0x432aff97, -0x546bdc59, -0x036c5fc7)
        RI4( 3, 10,  1,  8,  0x655b59c3, -0x70f3336e, -0x00100b83, -0x7a7ba22f)
        RI4(15,  6, 13,  4,  0x6fa87e4f, -0x01d31920, -0x5cfebcec, 0x4e0811a1)

        ROUND_I(A, B, C, D, "%[input11]", -0x08ac817e, 6)
        ROUND_I(D, A, B, C, "%[input2]" , -0x42c50dcb, 10)
        ROUND_I(C, D, A, B, "%[input9]" , 0x2ad7d2bb, 15)
        ROUND_I_LAST(B, C, D, A, -0x14792c6f, 21)
    : [TMP1]"+&R"(tmp1), [TMP2]"+&r"(tmp2),
      [A]"+&R"(A), [B]"+&R"(B), [C]"+&R"(C), [D]"+&R"(D)
    : INPUT_ARRAY
    :);

    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
}
#endif // defined(__x86_64__) || defined(__amd64__)
