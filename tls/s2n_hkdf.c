/******************************************************************************
Copyright (c) 2015 Cisco Systems, Inc.  All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the following
  disclaimer in the documentation and/or other materials provided
  with the distribution.
Neither the name of the Cisco Systems, Inc. nor the names of its
  contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
******************************************************************************/
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "s2n_hkdf.h"

static const EVP_MD* s2n_hkdf_get_evp_md(s2n_hmac_algorithm alg)
{
    switch (alg) {
    case S2N_HMAC_SHA256:
	return EVP_sha256();
	break;
    case S2N_HMAC_SHA384:
	return EVP_sha384();
	break;
    default:
	return NULL;
	break;
    }
}

int s2n_hkdf_get_hmac_size(s2n_hmac_algorithm alg)
{
    const EVP_MD *md = s2n_hkdf_get_evp_md(alg);
    if (!md) {
	return 0;
    } else {
	return EVP_MD_size(s2n_hkdf_get_evp_md(alg));
    }
}

int s2n_hkdf_extract(s2n_hmac_algorithm alg, struct s2n_blob *salt, struct s2n_blob *key, struct s2n_blob *prk)
{
    EVP_PKEY *mac_key;
    EVP_MD_CTX ctx;
    size_t h_len;
    const EVP_MD *md = s2n_hkdf_get_evp_md(alg);

    if (!md) return -1;

    mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, salt->data, salt->size);
    EVP_MD_CTX_init(&ctx);
    if (!EVP_DigestSignInit(&ctx, NULL, md, NULL, mac_key)) {
	return -1;
    }
    if (!EVP_DigestSignUpdate(&ctx, key->data, key->size)) {
	return -1;
    }
    if (!EVP_DigestSignFinal(&ctx, prk->data, &h_len)) {
	return -1;
    }
    prk->size = h_len;
    return 0;
}

static uint8_t s2n_hkdf_ceil(uint8_t num, uint8_t den)
{
    uint8_t remainder;

    if (den == 0) return 0;
    remainder = num%den;
    if (remainder) {
	return (num/den) + 1;
    } else {
	return (num/den);
    }

}

int s2n_hkdf_expand(s2n_hmac_algorithm alg, struct s2n_blob *prk, struct s2n_blob *info, uint8_t L, struct s2n_blob *okm)
{
    uint8_t N;
    uint8_t Thash[EVP_MAX_MD_SIZE];
    uint8_t Tsuf;
    EVP_PKEY *mac_key;
    EVP_MD_CTX ctx;
    size_t h_len;
    int hash_size;
    int tot_len = 0;
    int i;
    const EVP_MD *md = s2n_hkdf_get_evp_md(alg);

    if (!md) return -1;
    hash_size = EVP_MD_size(md);

    N = s2n_hkdf_ceil(L, prk->size);

    if (N>255) {
	return -1;
    }

    mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, prk->data, prk->size);
    EVP_MD_CTX_init(&ctx);

    Thash[0] = 0x0;
    h_len = 0;
    for (i=0; i<N; i++)
    {
	if (!EVP_DigestSignInit(&ctx, NULL, md, NULL, mac_key)) {
	    return -1;
	}
	if (!EVP_DigestSignUpdate(&ctx, Thash, h_len)) {
	    return -1;
	}
	if (!EVP_DigestSignUpdate(&ctx, info->data, info->size)) {
	    return -1;
	}
	Tsuf = i+1;
	if (!EVP_DigestSignUpdate(&ctx, &Tsuf, 1)) {
	    return -1;
	}
	if (!EVP_DigestSignFinal(&ctx, Thash, &h_len)) {
	    return -1;
	}
	if (h_len != hash_size) {
	    return -1;
	}
	memcpy((okm->data+(hash_size*i)), Thash, hash_size);
	tot_len += hash_size;
    }

    if (tot_len >= L) {
	okm->size = L;
    }

   return 0;
}

int s2n_hkdf_expand_label(s2n_hmac_algorithm alg, struct s2n_blob *secret, struct s2n_blob *label, 
	                  struct s2n_blob *hash, uint8_t L, struct s2n_blob *result)
{
    uint16_t hkdf_lbl_len;
    uint8_t *hkdf_lbl;
    struct s2n_blob hkdf_label;
    int rv;
    const EVP_MD *md = s2n_hkdf_get_evp_md(alg);

    if (!md) return -1;

    if (label->size > 255 || hash->size > 255) {
	return -1;
    }

    /*
     * We must construct HkdfLabel as:
     *    uint16_t length
     *    opaque hash_value<0..255>
     *    opaque label<9..255>
     *
     * Recall that a variable length opaque will have a size value
     * prefixed to the char array.  The size of the length value is
     * just large enough to hold the max length (8 bits in this case)
     *
     * First calculate the overall size of HkdfLabel
     */
    hkdf_lbl_len = sizeof(uint16_t) + hash->size + label->size + (2 * sizeof(uint8_t));
    hkdf_lbl = malloc(hkdf_lbl_len);
    if (!hkdf_lbl) {
	return -1;
    }
    hkdf_lbl[0] = 0;
    hkdf_lbl[1] = L;
    hkdf_lbl[2] = hash->size;
    memcpy(&hkdf_lbl[3], hash->data, hash->size);
    hkdf_lbl[hash->size+3] = label->size;
    memcpy(&hkdf_lbl[hash->size+4], label->data, label->size);
    s2n_blob_init(&hkdf_label, hkdf_lbl, hkdf_lbl_len);

    rv = s2n_hkdf_expand(alg, secret, &hkdf_label, L, result);

    s2n_blob_zero(&hkdf_label);
    free(hkdf_lbl);

    return (rv);
}

#if 0
//
//No makefile for this, here's how it's being compiled
//
//gcc -I.. -I../api s2n_hkdf.c -L../lib -lcrypto -ls2n -lpthread
//

static void dumphex(const char *label, uint8_t *data, uint16_t len)
{
    int i;

    printf("%s", label);
    for (i=0; i<len; i++) {
	printf("%02x ", data[i]);
    }
    printf("\n");
}


static uint8_t tc1_ikm[22] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b 
};
static uint8_t tc1_salt[13] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c
};
static uint8_t tc1_info[10] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9
};
static uint8_t tc1_L = 42;

static uint8_t tc1_okm[42]  = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
    0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
    0x58, 0x65
};

int main ()
{
    int rv;
    uint8_t *hkdf;
    uint8_t hkdf_len;
    uint8_t prk_data[EVP_MAX_MD_SIZE];
    uint8_t okm_data[EVP_MAX_MD_SIZE];


    struct s2n_blob salt;
    struct s2n_blob ikm;
    struct s2n_blob info;
    struct s2n_blob prk;
    struct s2n_blob okm;

    s2n_blob_init(&salt, tc1_salt, 13);
    s2n_blob_init(&ikm, tc1_ikm, 22);
    s2n_blob_init(&info, tc1_info, 10);
    s2n_blob_init(&prk, prk_data, 0);
    s2n_blob_init(&okm, okm_data, 0);

    rv = s2n_hkdf_extract(S2N_HMAC_SHA256, &salt, &ikm, &prk);
    if (!rv) {
	dumphex("PRK ", prk.data, prk.size);
    } else {
	printf("hkdf extract Failed\n");
	exit(1);
    }

    rv = s2n_hkdf_expand(S2N_HMAC_SHA256, &prk, &info, tc1_L, &okm);
    if (!rv) {
	if (okm.size != tc1_L) {
	    printf("Incorrect expansion length\n");
	    exit(1);
	}
	dumphex("OKM ", okm.data, okm.size);
	if (memcmp(okm.data, tc1_okm, tc1_L)) {
	    printf("OKM KAT fail\n");
	    exit(1);
	} else {
	    printf("Test passed!!!\n");
	}
    } else {
	printf("hkdf expand Failed\n");
	exit(1);
    }

#if 0
    rv = s2n_hkdf_expand_label(S2N_HMAC_SHA256, tc1_salt, 13, "expanded static secret", 22, tc1_okm, 32, &hkdf, &hkdf_len);
    if (!rv) {
	dumphex("HKDF ", hkdf, hkdf_len);
    } else {
	printf("hkdf expand label Failed\n");
	exit(1);
    }
#endif
}
#endif
