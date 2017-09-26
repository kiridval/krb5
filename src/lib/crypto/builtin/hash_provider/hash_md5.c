/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "crypto_int.h"
#include "rsa-md5.h"

#include "crypto_int.h"
#include "rsa-md5.h"
#include <string.h>
/**********************************************************************
 *                        gost89.c                                    *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *          Implementation of GOST 28147-89 encryption algorithm      *
 *            No OpenSSL libraries required to compile and use        *
 *                              this code                             *
 **********************************************************************/
#include "gost89.h"
#include "gosthash.h"

/*-
   Substitution blocks from RFC 4357

   Note: our implementation of gost 28147-89 algorithm
   uses S-box matrix rotated 90 degrees counterclockwise, relative to
   examples given in RFC.


*/

/* Substitution blocks from test examples for GOST R 34.11-94*/
gost_subst_block GostR3411_94_TestParamSet = {
    {0X1, 0XF, 0XD, 0X0, 0X5, 0X7, 0XA, 0X4, 0X9, 0X2, 0X3, 0XE, 0X6, 0XB,
     0X8, 0XC}
    ,
    {0XD, 0XB, 0X4, 0X1, 0X3, 0XF, 0X5, 0X9, 0X0, 0XA, 0XE, 0X7, 0X6, 0X8,
     0X2, 0XC}
    ,
    {0X4, 0XB, 0XA, 0X0, 0X7, 0X2, 0X1, 0XD, 0X3, 0X6, 0X8, 0X5, 0X9, 0XC,
     0XF, 0XE}
    ,
    {0X6, 0XC, 0X7, 0X1, 0X5, 0XF, 0XD, 0X8, 0X4, 0XA, 0X9, 0XE, 0X0, 0X3,
     0XB, 0X2}
    ,
    {0X7, 0XD, 0XA, 0X1, 0X0, 0X8, 0X9, 0XF, 0XE, 0X4, 0X6, 0XC, 0XB, 0X2,
     0X5, 0X3}
    ,
    {0X5, 0X8, 0X1, 0XD, 0XA, 0X3, 0X4, 0X2, 0XE, 0XF, 0XC, 0X7, 0X6, 0X0,
     0X9, 0XB}
    ,
    {0XE, 0XB, 0X4, 0XC, 0X6, 0XD, 0XF, 0XA, 0X2, 0X3, 0X8, 0X1, 0X0, 0X7,
     0X5, 0X9}
    ,
    {0X4, 0XA, 0X9, 0X2, 0XD, 0X8, 0X0, 0XE, 0X6, 0XB, 0X1, 0XC, 0X7, 0XF,
     0X5, 0X3}
};

/* Substitution blocks for hash function 1.2.643.2.9.1.6.1  */
gost_subst_block GostR3411_94_CryptoProParamSet = {
    {0x1, 0x3, 0xA, 0x9, 0x5, 0xB, 0x4, 0xF, 0x8, 0x6, 0x7, 0xE, 0xD, 0x0,
     0x2, 0xC}
    ,
    {0xD, 0xE, 0x4, 0x1, 0x7, 0x0, 0x5, 0xA, 0x3, 0xC, 0x8, 0xF, 0x6, 0x2,
     0x9, 0xB}
    ,
    {0x7, 0x6, 0x2, 0x4, 0xD, 0x9, 0xF, 0x0, 0xA, 0x1, 0x5, 0xB, 0x8, 0xE,
     0xC, 0x3}
    ,
    {0x7, 0x6, 0x4, 0xB, 0x9, 0xC, 0x2, 0xA, 0x1, 0x8, 0x0, 0xE, 0xF, 0xD,
     0x3, 0x5}
    ,
    {0x4, 0xA, 0x7, 0xC, 0x0, 0xF, 0x2, 0x8, 0xE, 0x1, 0x6, 0x5, 0xD, 0xB,
     0x9, 0x3}
    ,
    {0x7, 0xF, 0xC, 0xE, 0x9, 0x4, 0x1, 0x0, 0x3, 0xB, 0x5, 0x2, 0x6, 0xA,
     0x8, 0xD}
    ,
    {0x5, 0xF, 0x4, 0x0, 0x2, 0xD, 0xB, 0x9, 0x1, 0x7, 0x6, 0x3, 0xC, 0xE,
     0xA, 0x8}
    ,
    {0xA, 0x4, 0x5, 0x6, 0x8, 0x1, 0x3, 0x7, 0xD, 0xC, 0xE, 0x0, 0x9, 0x2,
     0xB, 0xF}
};

/* Test paramset from GOST 28147 */
gost_subst_block Gost28147_TestParamSet = {
    {0xC, 0x6, 0x5, 0x2, 0xB, 0x0, 0x9, 0xD, 0x3, 0xE, 0x7, 0xA, 0xF, 0x4,
     0x1, 0x8}
    ,
    {0x9, 0xB, 0xC, 0x0, 0x3, 0x6, 0x7, 0x5, 0x4, 0x8, 0xE, 0xF, 0x1, 0xA,
     0x2, 0xD}
    ,
    {0x8, 0xF, 0x6, 0xB, 0x1, 0x9, 0xC, 0x5, 0xD, 0x3, 0x7, 0xA, 0x0, 0xE,
     0x2, 0x4}
    ,
    {0x3, 0xE, 0x5, 0x9, 0x6, 0x8, 0x0, 0xD, 0xA, 0xB, 0x7, 0xC, 0x2, 0x1,
     0xF, 0x4}
    ,
    {0xE, 0x9, 0xB, 0x2, 0x5, 0xF, 0x7, 0x1, 0x0, 0xD, 0xC, 0x6, 0xA, 0x4,
     0x3, 0x8}
    ,
    {0xD, 0x8, 0xE, 0xC, 0x7, 0x3, 0x9, 0xA, 0x1, 0x5, 0x2, 0x4, 0x6, 0xF,
     0x0, 0xB}
    ,
    {0xC, 0x9, 0xF, 0xE, 0x8, 0x1, 0x3, 0xA, 0x2, 0x7, 0x4, 0xD, 0x6, 0x0,
     0xB, 0x5}
    ,
    {0x4, 0x2, 0xF, 0x5, 0x9, 0x1, 0x0, 0x8, 0xE, 0x3, 0xB, 0xC, 0xD, 0x7,
     0xA, 0x6}
};

/* 1.2.643.2.2.31.1 */
gost_subst_block Gost28147_CryptoProParamSetA = {
    {0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7,
     0xD, 0x4}
    ,
    {0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3,
     0xB, 0xE}
    ,
    {0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF,
     0xE, 0x6}
    ,
    {0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7,
     0xA, 0x6}
    ,
    {0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8,
     0x5, 0x6}
    ,
    {0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7,
     0x1, 0x9}
    ,
    {0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4,
     0xD, 0x1}
    ,
    {0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0,
     0xD, 0x5}
};

/* 1.2.643.2.2.31.2 */
gost_subst_block Gost28147_CryptoProParamSetB = {
    {0x0, 0x4, 0xB, 0xE, 0x8, 0x3, 0x7, 0x1, 0xA, 0x2, 0x9, 0x6, 0xF, 0xD,
     0x5, 0xC}
    ,
    {0x5, 0x2, 0xA, 0xB, 0x9, 0x1, 0xC, 0x3, 0x7, 0x4, 0xD, 0x0, 0x6, 0xF,
     0x8, 0xE}
    ,
    {0x8, 0x3, 0x2, 0x6, 0x4, 0xD, 0xE, 0xB, 0xC, 0x1, 0x7, 0xF, 0xA, 0x0,
     0x9, 0x5}
    ,
    {0x2, 0x7, 0xC, 0xF, 0x9, 0x5, 0xA, 0xB, 0x1, 0x4, 0x0, 0xD, 0x6, 0x8,
     0xE, 0x3}
    ,
    {0x7, 0x5, 0x0, 0xD, 0xB, 0x6, 0x1, 0x2, 0x3, 0xA, 0xC, 0xF, 0x4, 0xE,
     0x9, 0x8}
    ,
    {0xE, 0xC, 0x0, 0xA, 0x9, 0x2, 0xD, 0xB, 0x7, 0x5, 0x8, 0xF, 0x3, 0x6,
     0x1, 0x4}
    ,
    {0x0, 0x1, 0x2, 0xA, 0x4, 0xD, 0x5, 0xC, 0x9, 0x7, 0x3, 0xF, 0xB, 0x8,
     0x6, 0xE}
    ,
    {0x8, 0x4, 0xB, 0x1, 0x3, 0x5, 0x0, 0x9, 0x2, 0xE, 0xA, 0xC, 0xD, 0x6,
     0x7, 0xF}
};

/* 1.2.643.2.2.31.3 */
gost_subst_block Gost28147_CryptoProParamSetC = {
    {0x7, 0x4, 0x0, 0x5, 0xA, 0x2, 0xF, 0xE, 0xC, 0x6, 0x1, 0xB, 0xD, 0x9,
     0x3, 0x8}
    ,
    {0xA, 0x9, 0x6, 0x8, 0xD, 0xE, 0x2, 0x0, 0xF, 0x3, 0x5, 0xB, 0x4, 0x1,
     0xC, 0x7}
    ,
    {0xC, 0x9, 0xB, 0x1, 0x8, 0xE, 0x2, 0x4, 0x7, 0x3, 0x6, 0x5, 0xA, 0x0,
     0xF, 0xD}
    ,
    {0x8, 0xD, 0xB, 0x0, 0x4, 0x5, 0x1, 0x2, 0x9, 0x3, 0xC, 0xE, 0x6, 0xF,
     0xA, 0x7}
    ,
    {0x3, 0x6, 0x0, 0x1, 0x5, 0xD, 0xA, 0x8, 0xB, 0x2, 0x9, 0x7, 0xE, 0xF,
     0xC, 0x4}
    ,
    {0x8, 0x2, 0x5, 0x0, 0x4, 0x9, 0xF, 0xA, 0x3, 0x7, 0xC, 0xD, 0x6, 0xE,
     0x1, 0xB}
    ,
    {0x0, 0x1, 0x7, 0xD, 0xB, 0x4, 0x5, 0x2, 0x8, 0xE, 0xF, 0xC, 0x9, 0xA,
     0x6, 0x3}
    ,
    {0x1, 0xB, 0xC, 0x2, 0x9, 0xD, 0x0, 0xF, 0x4, 0x5, 0x8, 0xE, 0xA, 0x7,
     0x6, 0x3}
};

/* 1.2.643.2.2.31.4 */
gost_subst_block Gost28147_CryptoProParamSetD = {
    {0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD,
     0x2, 0xE}
    ,
    {0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA,
     0x5, 0x7}
    ,
    {0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9,
     0xD, 0x6}
    ,
    {0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE,
     0xF, 0x1}
    ,
    {0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3,
     0xF, 0x8}
    ,
    {0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3,
     0x7, 0x2}
    ,
    {0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA,
     0x9, 0x1}
    ,
    {0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB,
     0x8, 0x3}
};

/* 1.2.643.7.1.2.5.1.1 */
gost_subst_block Gost28147_TC26ParamSetZ = {
    {0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc,
     0xb, 0x2}
    ,
    {0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa,
     0x3, 0x7}
    ,
    {0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3,
     0xe, 0x0}
    ,
    {0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4,
     0x2, 0xc}
    ,
    {0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe,
     0x9, 0xb}
    ,
    {0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9,
     0x6, 0x0}
    ,
    {0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd,
     0x0, 0xf}
    ,
    {0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3,
     0xf, 0x1}
};

const byte CryptoProKeyMeshingKey[] = {
    0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
    0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
    0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
    0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B
};

/* Initialization of gost_ctx subst blocks*/
static void kboxinit(gost_ctx * c, const gost_subst_block * b)
{
    int i;

    for (i = 0; i < 256; i++) {
        c->k87[i] = (word32) (b->k8[i >> 4] << 4 | b->k7[i & 15]) << 24;
        c->k65[i] = (b->k6[i >> 4] << 4 | b->k5[i & 15]) << 16;
        c->k43[i] = (b->k4[i >> 4] << 4 | b->k3[i & 15]) << 8;
        c->k21[i] = b->k2[i >> 4] << 4 | b->k1[i & 15];

    }
}

/* Part of GOST 28147 algorithm moved into separate function */
static word32 f(gost_ctx * c, word32 x)
{
    x = c->k87[x >> 24 & 255] | c->k65[x >> 16 & 255] |
        c->k43[x >> 8 & 255] | c->k21[x & 255];
    /* Rotate left 11 bits */
    return x << 11 | x >> (32 - 11);
}

/* Low-level encryption routine - encrypts one 64 bit block*/
void gostcrypt(gost_ctx * c, const byte * in, byte * out)
{
    register word32 n1, n2;     /* As named in the GOST */
    n1 = in[0] | (in[1] << 8) | (in[2] << 16) | ((word32) in[3] << 24);
    n2 = in[4] | (in[5] << 8) | (in[6] << 16) | ((word32) in[7] << 24);
    /* Instead of swapping halves, swap names each round */

    n2 ^= f(c, n1 + c->k[0]);
    n1 ^= f(c, n2 + c->k[1]);
    n2 ^= f(c, n1 + c->k[2]);
    n1 ^= f(c, n2 + c->k[3]);
    n2 ^= f(c, n1 + c->k[4]);
    n1 ^= f(c, n2 + c->k[5]);
    n2 ^= f(c, n1 + c->k[6]);
    n1 ^= f(c, n2 + c->k[7]);

    n2 ^= f(c, n1 + c->k[0]);
    n1 ^= f(c, n2 + c->k[1]);
    n2 ^= f(c, n1 + c->k[2]);
    n1 ^= f(c, n2 + c->k[3]);
    n2 ^= f(c, n1 + c->k[4]);
    n1 ^= f(c, n2 + c->k[5]);
    n2 ^= f(c, n1 + c->k[6]);
    n1 ^= f(c, n2 + c->k[7]);

    n2 ^= f(c, n1 + c->k[0]);
    n1 ^= f(c, n2 + c->k[1]);
    n2 ^= f(c, n1 + c->k[2]);
    n1 ^= f(c, n2 + c->k[3]);
    n2 ^= f(c, n1 + c->k[4]);
    n1 ^= f(c, n2 + c->k[5]);
    n2 ^= f(c, n1 + c->k[6]);
    n1 ^= f(c, n2 + c->k[7]);

    n2 ^= f(c, n1 + c->k[7]);
    n1 ^= f(c, n2 + c->k[6]);
    n2 ^= f(c, n1 + c->k[5]);
    n1 ^= f(c, n2 + c->k[4]);
    n2 ^= f(c, n1 + c->k[3]);
    n1 ^= f(c, n2 + c->k[2]);
    n2 ^= f(c, n1 + c->k[1]);
    n1 ^= f(c, n2 + c->k[0]);

    out[0] = (byte) (n2 & 0xff);
    out[1] = (byte) ((n2 >> 8) & 0xff);
    out[2] = (byte) ((n2 >> 16) & 0xff);
    out[3] = (byte) (n2 >> 24);
    out[4] = (byte) (n1 & 0xff);
    out[5] = (byte) ((n1 >> 8) & 0xff);
    out[6] = (byte) ((n1 >> 16) & 0xff);
    out[7] = (byte) (n1 >> 24);
}

/* Low-level decryption routine. Decrypts one 64-bit block */
void gostdecrypt(gost_ctx * c, const byte * in, byte * out)
{
    register word32 n1, n2;     /* As named in the GOST */
    n1 = in[0] | (in[1] << 8) | (in[2] << 16) | ((word32) in[3] << 24);
    n2 = in[4] | (in[5] << 8) | (in[6] << 16) | ((word32) in[7] << 24);

    n2 ^= f(c, n1 + c->k[0]);
    n1 ^= f(c, n2 + c->k[1]);
    n2 ^= f(c, n1 + c->k[2]);
    n1 ^= f(c, n2 + c->k[3]);
    n2 ^= f(c, n1 + c->k[4]);
    n1 ^= f(c, n2 + c->k[5]);
    n2 ^= f(c, n1 + c->k[6]);
    n1 ^= f(c, n2 + c->k[7]);

    n2 ^= f(c, n1 + c->k[7]);
    n1 ^= f(c, n2 + c->k[6]);
    n2 ^= f(c, n1 + c->k[5]);
    n1 ^= f(c, n2 + c->k[4]);
    n2 ^= f(c, n1 + c->k[3]);
    n1 ^= f(c, n2 + c->k[2]);
    n2 ^= f(c, n1 + c->k[1]);
    n1 ^= f(c, n2 + c->k[0]);

    n2 ^= f(c, n1 + c->k[7]);
    n1 ^= f(c, n2 + c->k[6]);
    n2 ^= f(c, n1 + c->k[5]);
    n1 ^= f(c, n2 + c->k[4]);
    n2 ^= f(c, n1 + c->k[3]);
    n1 ^= f(c, n2 + c->k[2]);
    n2 ^= f(c, n1 + c->k[1]);
    n1 ^= f(c, n2 + c->k[0]);

    n2 ^= f(c, n1 + c->k[7]);
    n1 ^= f(c, n2 + c->k[6]);
    n2 ^= f(c, n1 + c->k[5]);
    n1 ^= f(c, n2 + c->k[4]);
    n2 ^= f(c, n1 + c->k[3]);
    n1 ^= f(c, n2 + c->k[2]);
    n2 ^= f(c, n1 + c->k[1]);
    n1 ^= f(c, n2 + c->k[0]);

    out[0] = (byte) (n2 & 0xff);
    out[1] = (byte) ((n2 >> 8) & 0xff);
    out[2] = (byte) ((n2 >> 16) & 0xff);
    out[3] = (byte) (n2 >> 24);
    out[4] = (byte) (n1 & 0xff);
    out[5] = (byte) ((n1 >> 8) & 0xff);
    out[6] = (byte) ((n1 >> 16) & 0xff);
    out[7] = (byte) (n1 >> 24);
}

/* Encrypts several blocks in ECB mode */
void gost_enc(gost_ctx * c, const byte * clear, byte * cipher, int blocks)
{
    int i;
    for (i = 0; i < blocks; i++) {
        gostcrypt(c, clear, cipher);
        clear += 8;
        cipher += 8;
    }
}

/* Decrypts several blocks in ECB mode */
void gost_dec(gost_ctx * c, const byte * cipher, byte * clear, int blocks)
{
    int i;
    for (i = 0; i < blocks; i++) {
        gostdecrypt(c, cipher, clear);
        clear += 8;
        cipher += 8;
    }
}

/* Encrypts several full blocks in CFB mode using 8byte IV */
void gost_enc_cfb(gost_ctx * ctx, const byte * iv, const byte * clear,
                  byte * cipher, int blocks)
{
    byte cur_iv[8];
    byte gamma[8];
    int i, j;
    const byte *in;
    byte *out;
    memcpy(cur_iv, iv, 8);
    for (i = 0, in = clear, out = cipher; i < blocks; i++, in += 8, out += 8) {
        gostcrypt(ctx, cur_iv, gamma);
        for (j = 0; j < 8; j++) {
            cur_iv[j] = out[j] = in[j] ^ gamma[j];
        }
    }
}

/* Decrypts several full blocks in CFB mode using 8byte IV */
void gost_dec_cfb(gost_ctx * ctx, const byte * iv, const byte * cipher,
                  byte * clear, int blocks)
{
    byte cur_iv[8];
    byte gamma[8];
    int i, j;
    const byte *in;
    byte *out;
    memcpy(cur_iv, iv, 8);
    for (i = 0, in = cipher, out = clear; i < blocks; i++, in += 8, out += 8) {
        gostcrypt(ctx, cur_iv, gamma);
        for (j = 0; j < 8; j++) {
            out[j] = (cur_iv[j] = in[j]) ^ gamma[j];
        }
    }
}

/* Encrypts one block using specified key */
void gost_enc_with_key(gost_ctx * c, byte * key, byte * inblock,
                       byte * outblock)
{
    gost_key(c, key);
    gostcrypt(c, inblock, outblock);
}

/* Set 256 bit  key into context */
void gost_key(gost_ctx * c, const byte * k)
{
    int i, j;
    for (i = 0, j = 0; i < 8; i++, j += 4) {
        c->k[i] =
            k[j] | (k[j + 1] << 8) | (k[j + 2] << 16) | ((word32) k[j + 3] <<
                                                         24);
    }
}

/* Retrieve 256-bit key from context */
void gost_get_key(gost_ctx * c, byte * k)
{
    int i, j;
    for (i = 0, j = 0; i < 8; i++, j += 4) {
        k[j] = (byte) (c->k[i] & 0xFF);
        k[j + 1] = (byte) ((c->k[i] >> 8) & 0xFF);
        k[j + 2] = (byte) ((c->k[i] >> 16) & 0xFF);
        k[j + 3] = (byte) ((c->k[i] >> 24) & 0xFF);
    }
}

/* Initalize context. Provides default value for subst_block */
void gost_init(gost_ctx * c, const gost_subst_block * b)
{
    if (!b) {
        b = &GostR3411_94_TestParamSet;
    }
    kboxinit(c, b);
}

/* Cleans up key from context */
void gost_destroy(gost_ctx * c)
{
    int i;
    for (i = 0; i < 8; i++)
        c->k[i] = 0;
}

/*
 * Compute GOST 28147 mac block Parameters gost_ctx *c - context initalized
 * with substitution blocks and key buffer - 8-byte mac state buffer block
 * 8-byte block to process.
 */
void mac_block(gost_ctx * c, byte * buffer, const byte * block)
{
    register word32 n1, n2;     /* As named in the GOST */
    int i;
    for (i = 0; i < 8; i++) {
        buffer[i] ^= block[i];
    }
    n1 = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | ((word32)
                                                             buffer[3] << 24);
    n2 = buffer[4] | (buffer[5] << 8) | (buffer[6] << 16) | ((word32)
                                                             buffer[7] << 24);
    /* Instead of swapping halves, swap names each round */

    n2 ^= f(c, n1 + c->k[0]);
    n1 ^= f(c, n2 + c->k[1]);
    n2 ^= f(c, n1 + c->k[2]);
    n1 ^= f(c, n2 + c->k[3]);
    n2 ^= f(c, n1 + c->k[4]);
    n1 ^= f(c, n2 + c->k[5]);
    n2 ^= f(c, n1 + c->k[6]);
    n1 ^= f(c, n2 + c->k[7]);

    n2 ^= f(c, n1 + c->k[0]);
    n1 ^= f(c, n2 + c->k[1]);
    n2 ^= f(c, n1 + c->k[2]);
    n1 ^= f(c, n2 + c->k[3]);
    n2 ^= f(c, n1 + c->k[4]);
    n1 ^= f(c, n2 + c->k[5]);
    n2 ^= f(c, n1 + c->k[6]);
    n1 ^= f(c, n2 + c->k[7]);

    buffer[0] = (byte) (n1 & 0xff);
    buffer[1] = (byte) ((n1 >> 8) & 0xff);
    buffer[2] = (byte) ((n1 >> 16) & 0xff);
    buffer[3] = (byte) (n1 >> 24);
    buffer[4] = (byte) (n2 & 0xff);
    buffer[5] = (byte) ((n2 >> 8) & 0xff);
    buffer[6] = (byte) ((n2 >> 16) & 0xff);
    buffer[7] = (byte) (n2 >> 24);
}

/* Get mac with specified number of bits from MAC state buffer */
void get_mac(byte * buffer, int nbits, byte * out)
{
    int nbytes = nbits >> 3;
    int rembits = nbits & 7;
    int mask = rembits ? ((1 < rembits) - 1) : 0;
    int i;
    for (i = 0; i < nbytes; i++)
        out[i] = buffer[i];
    if (rembits)
        out[i] = buffer[i] & mask;
}

/*
 * Compute mac of specified length (in bits) from data. Context should be
 * initialized with key and subst blocks
 */
int gost_mac(gost_ctx * ctx, int mac_len, const unsigned char *data,
             unsigned int data_len, unsigned char *mac)
{
    byte buffer[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    byte buf2[8];
    unsigned int i;
    for (i = 0; i + 8 <= data_len; i += 8)
        mac_block(ctx, buffer, data + i);
    if (i < data_len) {
        memset(buf2, 0, 8);
        memcpy(buf2, data + i, data_len - i);
        mac_block(ctx, buffer, buf2);
        i += 8;
    }
    if (i == 8) {
        memset(buf2, 0, 8);
        mac_block(ctx, buffer, buf2);
    }
    get_mac(buffer, mac_len, mac);
    return 1;
}

/* Compute MAC with non-zero IV. Used in some RFC 4357 algorithms */
int gost_mac_iv(gost_ctx * ctx, int mac_len, const unsigned char *iv,
                const unsigned char *data, unsigned int data_len,
                unsigned char *mac)
{
    byte buffer[8];
    byte buf2[8];
    unsigned int i;
    memcpy(buffer, iv, 8);
    for (i = 0; i + 8 <= data_len; i += 8)
        mac_block(ctx, buffer, data + i);
    if (i < data_len) {
        memset(buf2, 0, 8);
        memcpy(buf2, data + i, data_len - i);
        mac_block(ctx, buffer, buf2);
        i += 8;
    }
    if (i == 8) {
        memset(buf2, 0, 8);
        mac_block(ctx, buffer, buf2);
    }
    get_mac(buffer, mac_len, mac);
    return 1;
}

/* Implements key meshing algorithm by modifing ctx and IV in place */
void cryptopro_key_meshing(gost_ctx * ctx, unsigned char *iv)
{
    unsigned char newkey[32], newiv[8];
    /* Set static keymeshing key */
    /* "Decrypt" key with keymeshing key */
    gost_dec(ctx, CryptoProKeyMeshingKey, newkey, 4);
    /* set new key */
    gost_key(ctx, newkey);
    /* Encrypt iv with new key */
    gostcrypt(ctx, iv, newiv);
    memcpy(iv, newiv, 8);
}


/*
 * Use OPENSSL_malloc for memory allocation if compiled with
 * -DOPENSSL_BUILD, and libc malloc otherwise
 */
#ifndef MYALLOC
# ifdef OPENSSL_BUILD
#  include <openssl/crypto.h>
#  define MYALLOC(size) OPENSSL_malloc(size)
#  define MYFREE(ptr) OPENSSL_free(ptr)
# else
#  define MYALLOC(size) malloc(size)
#  define MYFREE(ptr) free(ptr)
# endif
#endif
/*
 * Following functions are various bit meshing routines used in GOST R
 * 34.11-94 algorithms
 */
static void swap_bytes(byte * w, byte * k)
{
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 8; j++)
            k[i + 4 * j] = w[8 * i + j];

}

/* was A_A */
static void circle_xor8(const byte * w, byte * k)
{
    byte buf[8];
    int i;
    memcpy(buf, w, 8);
    memmove(k, w + 8, 24);
    for (i = 0; i < 8; i++)
        k[i + 24] = buf[i] ^ k[i];
}

/* was R_R */
static void transform_3(byte * data)
{
    unsigned short int acc;
    acc = (data[0] ^ data[2] ^ data[4] ^ data[6] ^ data[24] ^ data[30]) |
        ((data[1] ^ data[3] ^ data[5] ^ data[7] ^ data[25] ^ data[31]) << 8);
    memmove(data, data + 2, 30);
    data[30] = acc & 0xff;
    data[31] = acc >> 8;
}

/* Adds blocks of N bytes modulo 2**(8*n). Returns carry*/
static int add_blocks(int n, byte * left, const byte * right)
{
    int i;
    int carry = 0;
    int sum;
    for (i = 0; i < n; i++) {
        sum = (int)left[i] + (int)right[i] + carry;
        left[i] = sum & 0xff;
        carry = sum >> 8;
    }
    return carry;
}

/* Xor two sequences of bytes */
static void xor_blocks(byte * result, const byte * a, const byte * b,
                       size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
        result[i] = a[i] ^ b[i];
}

/*
 *      Calculate H(i+1) = Hash(Hi,Mi)
 *      Where H and M are 32 bytes long
 */
static int hash_step(gost_ctx * c, byte * H, const byte * M)
{
    byte U[32], W[32], V[32], S[32], Key[32];
    int i;
    /* Compute first key */
    xor_blocks(W, H, M, 32);
    swap_bytes(W, Key);
    /* Encrypt first 8 bytes of H with first key */
    gost_enc_with_key(c, Key, H, S);
    /* Compute second key */
    circle_xor8(H, U);
    circle_xor8(M, V);
    circle_xor8(V, V);
    xor_blocks(W, U, V, 32);
    swap_bytes(W, Key);
    /* encrypt second 8 bytes of H with second key */
    gost_enc_with_key(c, Key, H + 8, S + 8);
    /* compute third key */
    circle_xor8(U, U);
    U[31] = ~U[31];
    U[29] = ~U[29];
    U[28] = ~U[28];
    U[24] = ~U[24];
    U[23] = ~U[23];
    U[20] = ~U[20];
    U[18] = ~U[18];
    U[17] = ~U[17];
    U[14] = ~U[14];
    U[12] = ~U[12];
    U[10] = ~U[10];
    U[8] = ~U[8];
    U[7] = ~U[7];
    U[5] = ~U[5];
    U[3] = ~U[3];
    U[1] = ~U[1];
    circle_xor8(V, V);
    circle_xor8(V, V);
    xor_blocks(W, U, V, 32);
    swap_bytes(W, Key);
    /* encrypt third 8 bytes of H with third key */
    gost_enc_with_key(c, Key, H + 16, S + 16);
    /* Compute fourth key */
    circle_xor8(U, U);
    circle_xor8(V, V);
    circle_xor8(V, V);
    xor_blocks(W, U, V, 32);
    swap_bytes(W, Key);
    /* Encrypt last 8 bytes with fourth key */
    gost_enc_with_key(c, Key, H + 24, S + 24);
    for (i = 0; i < 12; i++)
        transform_3(S);
    xor_blocks(S, S, M, 32);
    transform_3(S);
    xor_blocks(S, S, H, 32);
    for (i = 0; i < 61; i++)
        transform_3(S);
    memcpy(H, S, 32);
    return 1;
}

/*
 * Initialize gost_hash ctx - cleans up temporary structures and set up
 * substitution blocks
 */
int init_gost_hash_ctx(gost_hash_ctx * ctx,
                       const gost_subst_block * subst_block)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->cipher_ctx = (gost_ctx *) MYALLOC(sizeof(gost_ctx));
    if (!ctx->cipher_ctx) {
        return 0;
    }
    gost_init(ctx->cipher_ctx, subst_block);
    return 1;
}

/*
 * Free cipher CTX if it is dynamically allocated. Do not use
 * if cipher ctx is statically allocated as in OpenSSL implementation of
 * GOST hash algroritm
 *
 */
void done_gost_hash_ctx(gost_hash_ctx * ctx)
{
    /*
     * No need to use gost_destroy, because cipher keys are not really secret
     * when hashing
     */
    MYFREE(ctx->cipher_ctx);
}

/*
 * reset state of hash context to begin hashing new message
 */
int start_hash(gost_hash_ctx * ctx)
{
    if (!ctx->cipher_ctx)
        return 0;
    memset(&(ctx->H), 0, 32);
    memset(&(ctx->S), 0, 32);
    ctx->len = 0L;
    ctx->left = 0;
    return 1;
}

/*
 * Hash block of arbitrary length
 *
 *
 */
int hash_block(gost_hash_ctx * ctx, const byte * block, size_t length)
{
    if (ctx->left) {
        /*
         * There are some bytes from previous step
         */
        unsigned int add_bytes = 32 - ctx->left;
        if (add_bytes > length) {
            add_bytes = length;
        }
        memcpy(&(ctx->remainder[ctx->left]), block, add_bytes);
        ctx->left += add_bytes;
        if (ctx->left < 32) {
            return 1;
        }
        block += add_bytes;
        length -= add_bytes;
        hash_step(ctx->cipher_ctx, ctx->H, ctx->remainder);
        add_blocks(32, ctx->S, ctx->remainder);
        ctx->len += 32;
        ctx->left = 0;
    }
    while (length >= 32) {
        hash_step(ctx->cipher_ctx, ctx->H, block);

        add_blocks(32, ctx->S, block);
        ctx->len += 32;
        block += 32;
        length -= 32;
    }
    if (length) {
        memcpy(ctx->remainder, block, ctx->left = length);
    }
    return 1;
}

/*
 * Compute hash value from current state of ctx
 * state of hash ctx becomes invalid and cannot be used for further
 * hashing.
 */
int finish_hash(gost_hash_ctx * ctx, byte * hashval)
{
    byte buf[32];
    byte H[32];
    byte S[32];
    ghosthash_len fin_len = ctx->len;
    byte *bptr;
    memcpy(H, ctx->H, 32);
    memcpy(S, ctx->S, 32);
    if (ctx->left) {
        memset(buf, 0, 32);
        memcpy(buf, ctx->remainder, ctx->left);
        hash_step(ctx->cipher_ctx, H, buf);
        add_blocks(32, S, buf);
        fin_len += ctx->left;
    }
    memset(buf, 0, 32);
    if (fin_len == 0)
        hash_step(ctx->cipher_ctx, H, buf);
    bptr = buf;
    fin_len <<= 3;              /* Hash length in BITS!! */
    while (fin_len > 0) {
        *(bptr++) = (byte) (fin_len & 0xFF);
        fin_len >>= 8;
    };
    hash_step(ctx->cipher_ctx, H, buf);
    hash_step(ctx->cipher_ctx, H, S);
    memcpy(hashval, H, 32);
    return 1;
}

static krb5_error_code
k5_md5_hash(const krb5_crypto_iov *data, size_t num_data, krb5_data *output)
{
    krb5_MD5_CTX ctx;
    unsigned int i;

    if (output->length != RSA_MD5_CKSUM_LENGTH)
        return KRB5_CRYPTO_INTERNAL;

    krb5int_MD5Init(&ctx);
    for (i = 0; i < num_data; i++) {
        const krb5_crypto_iov *iov = &data[i];

        if (SIGN_IOV(iov)) {
            krb5int_MD5Update(&ctx, (unsigned char *) iov->data.data,
                              iov->data.length);
        }
    }
    krb5int_MD5Final(&ctx);

    memcpy(output->data, ctx.digest, RSA_MD5_CKSUM_LENGTH);

    return 0;
}

const struct krb5_hash_provider krb5int_hash_md5 = {
    "MD5",
    RSA_MD5_CKSUM_LENGTH,
    64,
    k5_md5_hash
};

static krb5_error_code
k5_gost_hash(const krb5_crypto_iov *data, size_t num_data, krb5_data *output)
{
	unsigned int i;
	gost_hash_ctx ctx;
	gost_subst_block *b = &GostR3411_94_CryptoProParamSet;
	init_gost_hash_ctx(&ctx, b);


	if (output->length != GOST_CKSUM_LENGTH)
		  return KRB5_CRYPTO_INTERNAL;

	for (i = 0; i < num_data; i++)
	{
		const krb5_crypto_iov *iov = &data[i];

		if (SIGN_IOV(iov))
		{
		    hash_block(&ctx, (unsigned char *) iov->data.data,
		    iov->data.length);
		}
	 }
      finish_hash(&ctx, output->data);

      return 0;
}

const struct krb5_hash_provider krb5int_hash_gost = {
    "gost",
	GOST_CKSUM_LENGTH,
    32,
	k5_gost_hash
};

