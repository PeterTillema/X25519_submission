#include "x25519.h"
#include <stdio.h>
#include <debug.h>

typedef uint8_t u8;
typedef long long i64;
typedef i64 field_elem[16];
static const u8 _9[32] = {9};
static const field_elem _121665 = {0xDB41, 1};

static void unpack25519(field_elem out, const u8* in) {
    for (u8 i = 0; i < 16; i++) {
        out[i] = in[2 * i] + ((i64)in[2 * i + 1] << 8);
    }
    out[15] &= 0x7FFF;
}

// Timing: 183,225 cc
static void carry25519(field_elem elem) {
    for (u8 i = 0; i < 16; i++) {
        const i64 carry = elem[i] >> 16;
        elem[i] -= carry << 16;
        if (i < 15) elem[i + 1] += carry;
        else elem[0] += 38 * carry;
    }
}

// Timing: 16,614 cc
static void fadd(field_elem out, const field_elem a, const field_elem b) {
    for (u8 i = 0; i < 16; i++) {
        out[i] = a[i] + b[i];
    }
}

// Timing: 15,958 cc
static void fsub(field_elem out, const field_elem a, const field_elem b) {
    for (u8 i = 0; i < 16; i++) {
        out[i] = a[i] - b[i];
    }
}

// Timing: 3,272,356 cc
// Timing: 3,271,092 cc
static void fmul(field_elem out, const field_elem a, const field_elem b) {
    i64 i, product[31];
    for (i = 0; i < 31; ++i) product[i] = 0;
    for (i = 0; i < 16; ++i) {
        for (i64 j = 0; j < 16; ++j) product[i + j] += a[i] * b[j];
    }
    for (i = 0; i < 15; ++i) product[i] += 38 * product[i + 16];
    for (i = 0; i < 16; ++i) out[i] = product[i];
    carry25519(out);
    carry25519(out);
}

static void finverse(field_elem out, const field_elem in) {
    field_elem c;
    int i;
    for (i = 0; i < 16; ++i) c[i] = in[i];
    for (i = 253; i >= 0; i--) {
        fmul(c, c, c);
        if (i != 2 && i != 4) fmul(c, c, in);
    }
    for (i = 0; i < 16; ++i) out[i] = c[i];
}

static void swap25519(field_elem p, field_elem q, const int bit) {
    const i64 c = ~(bit - 1);
    for (i64 i = 0; i < 16; ++i) {
        i64 t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(u8* out, const field_elem in) {
    int i;
    field_elem m, t;
    for (i = 0; i < 16; ++i) t[i] = in[i];
    carry25519(t);
    carry25519(t);
    carry25519(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int carry = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        swap25519(t, m, 1 - carry);
    }
    for (i = 0; i < 16; ++i) {
        out[2 * i] = t[i] & 0xff;
        out[2 * i + 1] = t[i] >> 8;
    }
}

void scalarmult(u8* out, const u8* scalar, const u8* point) {
    u8 clamped[32];
    int i;
    field_elem a, b, c, d, e, f, x;
    for (i = 0; i < 32; ++i) clamped[i] = scalar[i];
    clamped[0] &= 0xf8;
    clamped[31] = (clamped[31] & 0x7f) | 0x40;
    unpack25519(x, point);
    for (i = 0; i < 16; ++i) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
        const i64 bit = (clamped[i >> 3] >> (i & 7)) & 1;
        swap25519(a, b, bit);
        swap25519(c, d, bit);
        fadd(e, a, c);
        fsub(a, a, c);
        fadd(c, b, d);
        fsub(b, b, d);
        fmul(d, e, e);
        fmul(f, a, a);
        fmul(a, c, a);
        fmul(c, b, e);
        fadd(e, a, c);
        fsub(a, a, c);
        fmul(b, a, a);
        fsub(c, d, f);
        fmul(a, c, _121665);
        fadd(a, a, d);
        fmul(c, c, a);
        fmul(a, d, f);
        fmul(d, b, x);
        fmul(b, e, e);
        swap25519(a, b, bit);
        swap25519(c, d, bit);
        printf("Calculated %i/%i\n", i, 254);
    }
    finverse(c, c);
    fmul(a, a, c);
    pack25519(out, a);
}

// bool tls_x25519_publickey(
//     uint8_t public_key[32],
//     const uint8_t private_key[32],
//     void (*yield_fn)(void*),
//     void* yield_data
// ) {
//     scalarmult(public_key, private_key, _9);
//     return true;
// }

// bool tls_x25519_secret(
//     uint8_t shared_secret[32],
//     const uint8_t my_private[32],
//     const uint8_t their_public[32],
//     void (*yield_fn)(void*),
//     void* yield_data
// ) {
//     return true;
// }
