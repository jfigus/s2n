/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_prf.h"
#include "tls/s2n_hkdf.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hmac.h"
#include "crypto/s2n_hash.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

static int s2n_sslv3_prf(union s2n_prf_working_space *ws, struct s2n_blob *secret, struct s2n_blob *seed_a, struct s2n_blob *seed_b, struct s2n_blob *out)
{
    struct s2n_hash_state *md5 = &ws->ssl3.md5;
    struct s2n_hash_state *sha1 = &ws->ssl3.sha1;

    uint32_t outputlen = out->size;
    uint8_t *output = out->data;
    uint8_t iteration = 1;

    uint8_t A = 'A';
    while (outputlen) {
        GUARD(s2n_hash_init(sha1, S2N_HASH_SHA1));

        for (int i = 0; i < iteration; i++) {
            GUARD(s2n_hash_update(sha1, &A, 1));
        }

        GUARD(s2n_hash_update(sha1, secret->data, secret->size));
        GUARD(s2n_hash_update(sha1, seed_a->data, seed_a->size));

        if (seed_b) {
            GUARD(s2n_hash_update(sha1, seed_b->data, seed_b->size));
        }

        GUARD(s2n_hash_digest(sha1, ws->ssl3.sha1_digest, sizeof(ws->ssl3.sha1_digest)));
        GUARD(s2n_hash_init(md5, S2N_HASH_MD5));
        GUARD(s2n_hash_update(md5, secret->data, secret->size));
        GUARD(s2n_hash_update(md5, ws->ssl3.sha1_digest, sizeof(ws->ssl3.sha1_digest)));
        GUARD(s2n_hash_digest(md5, ws->ssl3.md5_digest, sizeof(ws->ssl3.md5_digest)));

        uint32_t bytes_to_copy = outputlen;
        if (bytes_to_copy > sizeof(ws->ssl3.md5_digest)) {
            bytes_to_copy = sizeof(ws->ssl3.md5_digest);
        }

        memcpy_check(output, ws->ssl3.md5_digest, bytes_to_copy);

        outputlen -= bytes_to_copy;
        output += bytes_to_copy;

        /* Increment the letter */
        A++;
        iteration++;
    }

    return 0;
}

static int s2n_p_hash(union s2n_prf_working_space *ws, s2n_hmac_algorithm alg, struct s2n_blob *secret,
                      struct s2n_blob *label, struct s2n_blob *seed_a, struct s2n_blob *seed_b, struct s2n_blob *out)
{
    struct s2n_hmac_state *hmac = &ws->tls.hmac;
    uint32_t digest_size = s2n_hmac_digest_size(alg);

    /* First compute hmac(secret + A(0)) */
    GUARD(s2n_hmac_init(hmac, alg, secret->data, secret->size));
    GUARD(s2n_hmac_update(hmac, label->data, label->size));
    GUARD(s2n_hmac_update(hmac, seed_a->data, seed_a->size));

    if (seed_b) {
        GUARD(s2n_hmac_update(hmac, seed_b->data, seed_b->size));
    }
    GUARD(s2n_hmac_digest(hmac, ws->tls.digest0, digest_size));

    uint32_t outputlen = out->size;
    uint8_t *output = out->data;

    while (outputlen) {
        /* Now compute hmac(secret + A(N - 1) + seed) */
        GUARD(s2n_hmac_reset(hmac));
        GUARD(s2n_hmac_update(hmac, ws->tls.digest0, digest_size));

        /* Add the label + seed and compute this round's A */
        GUARD(s2n_hmac_update(hmac, label->data, label->size));
        GUARD(s2n_hmac_update(hmac, seed_a->data, seed_a->size));
        if (seed_b) {
            GUARD(s2n_hmac_update(hmac, seed_b->data, seed_b->size));
        }
        GUARD(s2n_hmac_digest(hmac, ws->tls.digest1, digest_size));

        uint32_t bytes_to_xor = outputlen;
        if (bytes_to_xor > digest_size) {
            bytes_to_xor = digest_size;
        }

        for (int i = 0; i < bytes_to_xor; i++) {
            *output ^= ws->tls.digest1[i];
            output++;
            outputlen--;
        }

        /* Stash a digest of A(N), in A(N), for the next round */
        GUARD(s2n_hmac_reset(hmac));
        GUARD(s2n_hmac_update(hmac, ws->tls.digest0, digest_size));
        GUARD(s2n_hmac_digest(hmac, ws->tls.digest0, digest_size));
    }

    return 0;
}

static int s2n_prf(struct s2n_connection *conn, struct s2n_blob *secret, struct s2n_blob *label, struct s2n_blob *seed_a, struct s2n_blob *seed_b, struct s2n_blob *out)
{
    if (conn->actual_protocol_version == S2N_SSLv3) {
        return s2n_sslv3_prf(&conn->prf_space, secret, seed_a, seed_b, out);
    }

    /* We zero the out blob because p_hash works by XOR'ing with the existing
     * buffer. This is a little convuloted but means we can avoid dynamic memory
     * allocation. When we call p_hash once (in the TLS1.2 case) it will produce
     * the right values. When we call it twice in the regular case, the two
     * outputs will be XORd just ass the TLS 1.0 and 1.1 RFCs require.
     */
    GUARD(s2n_blob_zero(out));

    if (conn->actual_protocol_version >= S2N_TLS12) {
        return s2n_p_hash(&conn->prf_space, S2N_HMAC_SHA256, secret, label, seed_a, seed_b, out);
    }

    struct s2n_blob half_secret = {.data = secret->data,.size = (secret->size + 1) / 2 };

    GUARD(s2n_p_hash(&conn->prf_space, S2N_HMAC_MD5, &half_secret, label, seed_a, seed_b, out));
    half_secret.data += secret->size - half_secret.size;
    GUARD(s2n_p_hash(&conn->prf_space, S2N_HMAC_SHA1, &half_secret, label, seed_a, seed_b, out));

    return 0;
}

/*
 * Generates the xES value as defined in section 7.1 of rev10
 * and does key expansion for the handshake message protection as
 * defined in 7.2.
 */
int s2n_tls13_prf_ephemeral_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret)
{
    struct s2n_blob hand_hash;
    struct s2n_blob xES;
    struct s2n_blob mESlabel;
    struct s2n_blob zero;
    uint8_t exp_es_label[] = "handshake key expansion";
    s2n_hmac_algorithm hmac_alg;
    uint8_t dataxES[EVP_MAX_MD_SIZE];
    uint8_t hash_digest[EVP_MAX_MD_SIZE];
    struct s2n_blob out;
    uint8_t key_block[128];
    struct s2n_stuffer key_material;
    struct s2n_blob client_key;
    struct s2n_blob server_key;

    S2N_DEBUG_ENTER;

    /*
     * Get the hash to use from the cipher suite
     */
    hmac_alg = conn->pending.cipher_suite->hmac_alg;

    /*
     * We shouldn't have to do this, but the record layer in s2n always
     * uses the HMAC, even for AEAD ciphers.  Probably need to fix the
     * record layer and we can remove this HMAC init logic here.
     */

    /*
     * Get the current handshake hash up to this point in the handshake
     */
    //FIXME: hard-coded to sha-256, it needs to derive from negotiated cipher suite 
    GUARD(s2n_hash_digest(&conn->handshake.server_sha256, hash_digest, SHA256_DIGEST_LENGTH));
    s2n_blob_init(&hand_hash, hash_digest, SHA256_DIGEST_LENGTH);
    s2n_debug_dumphex("handshake_hash: ", hand_hash.data, hand_hash.size);

    /*
     * Calculate xES
     */
    s2n_blob_init(&zero, NULL, 0);
    s2n_blob_init(&xES, dataxES, 0);
    GUARD(s2n_hkdf_extract(hmac_alg, &zero, premaster_secret, &xES));
    s2n_debug_dumphex("xES: ", xES.data, xES.size);

    /*
     * Expand xES to derive key material
     */
    s2n_blob_init(&mESlabel, exp_es_label, sizeof(exp_es_label));
    s2n_blob_init(&out, key_block, sizeof(key_block));
    GUARD(s2n_hkdf_expand_label(hmac_alg, &xES, &mESlabel, &hand_hash, out.size, &out));
    s2n_debug_dumphex("keyblock: ", out.data, out.size);

    GUARD(s2n_stuffer_init(&key_material, &out));
    GUARD(s2n_stuffer_write(&key_material, &out));

    int mac_size;
    GUARD((mac_size = s2n_hmac_digest_size(hmac_alg)));

    //FIXME: Not sure why we need MAC keys, this needs to go away.  But the s2n record
    //       layer always does the MAC calculation, even for AEAD ciphers.  Not sure why.
    /* Seed the client MAC */
    uint8_t *client_write_mac_key = s2n_stuffer_raw_read(&key_material, mac_size);
    notnull_check(client_write_mac_key);
    GUARD(s2n_hmac_init(&conn->pending.client_record_mac, hmac_alg, client_write_mac_key, mac_size));

    /* Seed the server MAC */
    uint8_t *server_write_mac_key = s2n_stuffer_raw_read(&key_material, mac_size);
    notnull_check(server_write_mac_key);
    GUARD(s2n_hmac_init(&conn->pending.server_record_mac, hmac_alg, server_write_mac_key, mac_size));

    /* Make the client key */
    client_key.size = conn->pending.cipher_suite->cipher->key_material_size;
    client_key.data = s2n_stuffer_raw_read(&key_material, client_key.size);
    s2n_debug_dumphex("clientkey: ", client_key.data, client_key.size);
    notnull_check(client_key.data);
    if (conn->mode == S2N_CLIENT) {
        GUARD(conn->pending.cipher_suite->cipher->get_encryption_key(&conn->pending.client_key, &client_key));
    } else {
        GUARD(conn->pending.cipher_suite->cipher->get_decryption_key(&conn->pending.client_key, &client_key));
    }

    /* Make the server key */
    server_key.size = conn->pending.cipher_suite->cipher->key_material_size;
    server_key.data = s2n_stuffer_raw_read(&key_material, server_key.size);
    s2n_debug_dumphex("serverkey: ", server_key.data, server_key.size);
    notnull_check(server_key.data);
    if (conn->mode == S2N_SERVER) {
        GUARD(conn->pending.cipher_suite->cipher->get_encryption_key(&conn->pending.server_key, &server_key));
    } else {
        GUARD(conn->pending.cipher_suite->cipher->get_decryption_key(&conn->pending.server_key, &server_key));
    }

    if (conn->pending.cipher_suite->cipher->type == S2N_AEAD) {
        /* Generate the IVs */
        struct s2n_blob client_implicit_iv;
        client_implicit_iv.data = conn->pending.client_implicit_iv;
        client_implicit_iv.size = conn->pending.cipher_suite->cipher->io.aead.fixed_iv_size;
        GUARD(s2n_stuffer_read(&key_material, &client_implicit_iv));
	s2n_debug_dumphex("client_implicit_iv: ", client_implicit_iv.data, client_implicit_iv.size);

        struct s2n_blob server_implicit_iv;
        server_implicit_iv.data = conn->pending.server_implicit_iv;
        server_implicit_iv.size = conn->pending.cipher_suite->cipher->io.aead.fixed_iv_size;
        GUARD(s2n_stuffer_read(&key_material, &server_implicit_iv));
	s2n_debug_dumphex("server_implicit_iv: ", server_implicit_iv.data, server_implicit_iv.size);
    } 

    S2N_DEBUG_EXIT;

    return 0;
}

/*
 * Generates the master_secret value as defined in section 7.1 of rev10
 */
int s2n_tls13_prf_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret)
{
    struct s2n_blob master_secret;
    struct s2n_blob hand_hash;
    struct s2n_blob xSS;
    struct s2n_blob *xES;
    struct s2n_blob mSS;
    struct s2n_blob mES;
    struct s2n_blob mSSlabel;
    struct s2n_blob mESlabel;
    struct s2n_blob zero;
    uint8_t exp_ss_label[] = "expanded static secret";
    uint8_t exp_es_label[] = "expanded ephemeral secret";
    s2n_hmac_algorithm hmac_alg;
    uint8_t dataxSS[EVP_MAX_MD_SIZE];
    uint8_t datamSS[EVP_MAX_MD_SIZE];
    uint8_t datamES[EVP_MAX_MD_SIZE];
    uint8_t L;
    uint8_t hash_digest[EVP_MAX_MD_SIZE];

    S2N_DEBUG_ENTER;

    /*
     * Get the hash to use from the cipher suite
     */
    hmac_alg = conn->pending.cipher_suite->hmac_alg;
    L = (uint8_t) s2n_hkdf_get_hmac_size(hmac_alg);
    if (L <= 0 || L > sizeof(conn->pending.master_secret)) return -1;

    /*
     * Get the current handshake hash up to this point in the handshake
     */
    //FIXME: hard-coded to sha-256, it needs to derive from negotiated cipher suite 
    //FIXME: need to use the entire handshake hash, this is only through serverhello
    GUARD(s2n_hash_digest(&conn->handshake.server_sha256, hash_digest, SHA256_DIGEST_LENGTH));
    s2n_blob_init(&hand_hash, hash_digest, SHA256_DIGEST_LENGTH);
    s2n_debug_dumphex("handshake_hash: ", hand_hash.data, hand_hash.size);

    /*
     * Calculate xSS and xES
     * FIXME: for now, xSS and xES are the same for 1-RTT.  We will only to xSS
     */
    s2n_blob_init(&zero, NULL, 0);
    s2n_blob_init(&xSS, dataxSS, 0);
    GUARD(s2n_hkdf_extract(hmac_alg, &zero, premaster_secret, &xSS));
    s2n_debug_dumphex("xSS: ", xSS.data, xSS.size);
    xES = &xSS;

    /*
     * Calculate mSS and mES
     */
    s2n_blob_init(&mSS, datamSS, 0);
    s2n_blob_init(&mSSlabel, exp_ss_label, sizeof(exp_ss_label));
    GUARD(s2n_hkdf_expand_label(hmac_alg, &xSS, &mSSlabel, &hand_hash, L, &mSS));
    s2n_debug_dumphex("mSS: ", mSS.data, mSS.size);

    s2n_blob_init(&mES, datamES, 0);
    s2n_blob_init(&mESlabel, exp_es_label, sizeof(exp_es_label));
    GUARD(s2n_hkdf_expand_label(hmac_alg, xES, &mESlabel, &hand_hash, L, &mES));
    s2n_debug_dumphex("mSS: ", mES.data, mES.size);
    s2n_blob_zero(&hand_hash);

    /*
     * Calculate the master_secret
     */

    master_secret.data = conn->pending.master_secret;
    master_secret.size = L;
    conn->pending.master_secret_len = L;
    GUARD(s2n_hkdf_extract(hmac_alg, &mSS, &mES, &master_secret));
    s2n_debug_dumphex("mast secr: ", master_secret.data, master_secret.size);

    return 0;
}

int s2n_prf_master_secret(struct s2n_connection *conn, struct s2n_blob *premaster_secret)
{
    struct s2n_blob client_random, server_random, master_secret;
    struct s2n_blob label;
    uint8_t master_secret_label[] = "master secret";

    S2N_DEBUG_ENTER;

    client_random.data = conn->pending.client_random;
    client_random.size = sizeof(conn->pending.client_random);
    server_random.data = conn->pending.server_random;
    server_random.size = sizeof(conn->pending.server_random);
    master_secret.data = conn->pending.master_secret;
    master_secret.size = sizeof(conn->pending.master_secret);
    label.data = master_secret_label;
    label.size = sizeof(master_secret_label) - 1;

    s2n_debug_dumphex("clnt rand: ", client_random.data, client_random.size);
    s2n_debug_dumphex("srvr rand: ", server_random.data, server_random.size);
    s2n_debug_dumphex("premaster: ", premaster_secret->data, premaster_secret->size);
    s2n_debug_dumphex("mast secr: ", master_secret.data, master_secret.size);

    return s2n_prf(conn, premaster_secret, &label, &client_random, &server_random, &master_secret);
}

static int s2n_sslv3_finished(struct s2n_connection *conn, uint8_t prefix[4], struct s2n_hash_state *md5, struct s2n_hash_state *sha1, uint8_t *out)
{
    uint8_t xorpad1[48] =
        { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
        0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
    };
    uint8_t xorpad2[48] =
        { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
        0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
    };
    uint8_t *md5_digest = out;
    uint8_t *sha_digest = out + MD5_DIGEST_LENGTH;

    lte_check(MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH, sizeof(conn->handshake.client_finished));

    GUARD(s2n_hash_update(md5, prefix, 4));
    GUARD(s2n_hash_update(md5, conn->pending.master_secret, conn->pending.master_secret_len));
    GUARD(s2n_hash_update(md5, xorpad1, 48));
    GUARD(s2n_hash_digest(md5, md5_digest, MD5_DIGEST_LENGTH));
    GUARD(s2n_hash_reset(md5));
    GUARD(s2n_hash_update(md5, conn->pending.master_secret, conn->pending.master_secret_len));
    GUARD(s2n_hash_update(md5, xorpad2, 48));
    GUARD(s2n_hash_update(md5, md5_digest, MD5_DIGEST_LENGTH));
    GUARD(s2n_hash_digest(md5, md5_digest, MD5_DIGEST_LENGTH));
    GUARD(s2n_hash_reset(md5));

    GUARD(s2n_hash_update(sha1, prefix, 4));
    GUARD(s2n_hash_update(sha1, conn->pending.master_secret, conn->pending.master_secret_len));
    GUARD(s2n_hash_update(sha1, xorpad1, 40));
    GUARD(s2n_hash_digest(sha1, sha_digest, SHA_DIGEST_LENGTH));
    GUARD(s2n_hash_reset(sha1));
    GUARD(s2n_hash_update(sha1, conn->pending.master_secret, conn->pending.master_secret_len));
    GUARD(s2n_hash_update(sha1, xorpad2, 40));
    GUARD(s2n_hash_update(sha1, sha_digest, SHA_DIGEST_LENGTH));
    GUARD(s2n_hash_digest(sha1, sha_digest, SHA_DIGEST_LENGTH));
    GUARD(s2n_hash_reset(sha1));

    return 0;
}

static int s2n_sslv3_client_finished(struct s2n_connection *conn)
{
    uint8_t prefix[4] = { 0x43, 0x4c, 0x4e, 0x54 };

    lte_check(MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH, sizeof(conn->handshake.client_finished));
    return s2n_sslv3_finished(conn, prefix, &conn->handshake.client_md5, &conn->handshake.client_sha1, conn->handshake.client_finished);
}

static int s2n_sslv3_server_finished(struct s2n_connection *conn)
{
    uint8_t prefix[4] = { 0x53, 0x52, 0x56, 0x52 };

    lte_check(MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH, sizeof(conn->handshake.server_finished));
    return s2n_sslv3_finished(conn, prefix, &conn->handshake.server_md5, &conn->handshake.server_sha1, conn->handshake.server_finished);
}

int s2n_prf_client_finished(struct s2n_connection *conn)
{
    struct s2n_blob master_secret, md5, sha;
    uint8_t md5_digest[MD5_DIGEST_LENGTH];
    uint8_t sha_digest[SHA256_DIGEST_LENGTH];
    uint8_t client_finished_label[] = "client finished";
    struct s2n_blob client_finished;
    struct s2n_blob label;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        return s2n_sslv3_client_finished(conn);
    }

    client_finished.data = conn->handshake.client_finished;
    client_finished.size = S2N_TLS_FINISHED_LEN;
    label.data = client_finished_label;
    label.size = sizeof(client_finished_label) - 1;

    master_secret.data = conn->pending.master_secret;
    master_secret.size = conn->pending.master_secret_len;
    if (conn->actual_protocol_version >= S2N_TLS12) {
        GUARD(s2n_hash_digest(&conn->handshake.client_sha256, sha_digest, SHA256_DIGEST_LENGTH));
        sha.data = sha_digest;
        sha.size = SHA256_DIGEST_LENGTH;

        return s2n_prf(conn, &master_secret, &label, &sha, NULL, &client_finished);
    }

    GUARD(s2n_hash_digest(&conn->handshake.client_md5, md5_digest, MD5_DIGEST_LENGTH));
    GUARD(s2n_hash_digest(&conn->handshake.client_sha1, sha_digest, SHA_DIGEST_LENGTH));
    md5.data = md5_digest;
    md5.size = MD5_DIGEST_LENGTH;
    sha.data = sha_digest;
    sha.size = SHA_DIGEST_LENGTH;

    return s2n_prf(conn, &master_secret, &label, &md5, &sha, &client_finished);
}

int s2n_prf_server_finished(struct s2n_connection *conn)
{
    struct s2n_blob master_secret, md5, sha;
    uint8_t md5_digest[MD5_DIGEST_LENGTH];
    uint8_t sha_digest[SHA256_DIGEST_LENGTH];
    uint8_t server_finished_label[] = "server finished";
    struct s2n_blob server_finished;
    struct s2n_blob label;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        return s2n_sslv3_server_finished(conn);
    }

    server_finished.data = conn->handshake.server_finished;
    server_finished.size = S2N_TLS_FINISHED_LEN;
    label.data = server_finished_label;
    label.size = sizeof(server_finished_label) - 1;

    master_secret.data = conn->pending.master_secret;
    master_secret.size = conn->pending.master_secret_len;
    if (conn->actual_protocol_version >= S2N_TLS12) {
        GUARD(s2n_hash_digest(&conn->handshake.server_sha256, sha_digest, SHA256_DIGEST_LENGTH));
        sha.data = sha_digest;
        sha.size = SHA256_DIGEST_LENGTH;

        return s2n_prf(conn, &master_secret, &label, &sha, NULL, &server_finished);
    }

    GUARD(s2n_hash_digest(&conn->handshake.server_md5, md5_digest, MD5_DIGEST_LENGTH));
    GUARD(s2n_hash_digest(&conn->handshake.server_sha1, sha_digest, SHA_DIGEST_LENGTH));
    md5.data = md5_digest;
    md5.size = MD5_DIGEST_LENGTH;
    sha.data = sha_digest;
    sha.size = SHA_DIGEST_LENGTH;

    return s2n_prf(conn, &master_secret, &label, &md5, &sha, &server_finished);
}

int s2n_prf_key_expansion(struct s2n_connection *conn)
{
    struct s2n_blob client_random = {.data = conn->pending.client_random,.size = sizeof(conn->pending.client_random) };
    struct s2n_blob server_random = {.data = conn->pending.server_random,.size = sizeof(conn->pending.server_random) };
    struct s2n_blob master_secret = {.data = conn->pending.master_secret,.size = conn->pending.master_secret_len };
    struct s2n_blob label, out;
    uint8_t key_expansion_label[] = "key expansion";
    uint8_t key_block[128];

    S2N_DEBUG_ENTER;
    s2n_debug_dumphex("clnt rand: ", client_random.data, client_random.size);
    s2n_debug_dumphex("srvr rand: ", server_random.data, server_random.size);
    s2n_debug_dumphex("mast secr: ", master_secret.data, master_secret.size);


    label.data = key_expansion_label;
    label.size = sizeof(key_expansion_label) - 1;
    out.data = key_block;
    out.size = sizeof(key_block);

    struct s2n_stuffer key_material;
    GUARD(s2n_prf(conn, &master_secret, &label, &server_random, &client_random, &out));
    GUARD(s2n_stuffer_init(&key_material, &out));
    GUARD(s2n_stuffer_write(&key_material, &out));

    /* What's our hmac algorithm? */
    s2n_hmac_algorithm hmac_alg = conn->pending.cipher_suite->hmac_alg;
    if (conn->actual_protocol_version == S2N_SSLv3) {
        if (hmac_alg == S2N_HMAC_SHA1) {
            hmac_alg = S2N_HMAC_SSLv3_SHA1;
        } else if (hmac_alg == S2N_HMAC_MD5) {
            hmac_alg = S2N_HMAC_SSLv3_MD5;
        } else {
            S2N_ERROR(S2N_ERR_HMAC_INVALID_ALGORITHM);
        }
    }

    /* Check that we have a valid MAC and key size */
    int mac_size;
    GUARD((mac_size = s2n_hmac_digest_size(hmac_alg)));

    /* Seed the client MAC */
    uint8_t *client_write_mac_key = s2n_stuffer_raw_read(&key_material, mac_size);
    notnull_check(client_write_mac_key);
    GUARD(s2n_hmac_init(&conn->pending.client_record_mac, hmac_alg, client_write_mac_key, mac_size));

    /* Seed the server MAC */
    uint8_t *server_write_mac_key = s2n_stuffer_raw_read(&key_material, mac_size);
    notnull_check(server_write_mac_key);
    GUARD(s2n_hmac_init(&conn->pending.server_record_mac, hmac_alg, server_write_mac_key, mac_size));

    /* Make the client key */
    struct s2n_blob client_key;
    client_key.size = conn->pending.cipher_suite->cipher->key_material_size;
    client_key.data = s2n_stuffer_raw_read(&key_material, client_key.size);
    notnull_check(client_key.data);
    if (conn->mode == S2N_CLIENT) {
        GUARD(conn->pending.cipher_suite->cipher->get_encryption_key(&conn->pending.client_key, &client_key));
    } else {
        GUARD(conn->pending.cipher_suite->cipher->get_decryption_key(&conn->pending.client_key, &client_key));
    }

    /* Make the server key */
    struct s2n_blob server_key;
    server_key.size = conn->pending.cipher_suite->cipher->key_material_size;
    server_key.data = s2n_stuffer_raw_read(&key_material, server_key.size);
    notnull_check(server_key.data);
    if (conn->mode == S2N_SERVER) {
        GUARD(conn->pending.cipher_suite->cipher->get_encryption_key(&conn->pending.server_key, &server_key));
    } else {
        GUARD(conn->pending.cipher_suite->cipher->get_decryption_key(&conn->pending.server_key, &server_key));
    }

    /* TLS >= 1.1 has no implicit IVs for non AEAD ciphers */
    if (conn->actual_protocol_version > S2N_TLS10 &&
        conn->pending.cipher_suite->cipher->type != S2N_AEAD) {
        return 0;
    }

    if (conn->pending.cipher_suite->cipher->type == S2N_AEAD) {
        /* Generate the IVs */
        struct s2n_blob client_implicit_iv;
        client_implicit_iv.data = conn->pending.client_implicit_iv;
        client_implicit_iv.size = conn->pending.cipher_suite->cipher->io.aead.fixed_iv_size;
        GUARD(s2n_stuffer_read(&key_material, &client_implicit_iv));

        struct s2n_blob server_implicit_iv;
        server_implicit_iv.data = conn->pending.server_implicit_iv;
        server_implicit_iv.size = conn->pending.cipher_suite->cipher->io.aead.fixed_iv_size;
        GUARD(s2n_stuffer_read(&key_material, &server_implicit_iv));
    } else if (conn->pending.cipher_suite->cipher->type == S2N_CBC) {
        /* Generate the IVs */
        struct s2n_blob client_implicit_iv;
        client_implicit_iv.data = conn->pending.client_implicit_iv;
        client_implicit_iv.size = conn->pending.cipher_suite->cipher->io.cbc.block_size;
        GUARD(s2n_stuffer_read(&key_material, &client_implicit_iv));

        struct s2n_blob server_implicit_iv;
        server_implicit_iv.data = conn->pending.server_implicit_iv;
        server_implicit_iv.size = conn->pending.cipher_suite->cipher->io.cbc.block_size;
        GUARD(s2n_stuffer_read(&key_material, &server_implicit_iv));
    }

    return 0;
}

int s2n_tls13_prf_key_expansion(struct s2n_connection *conn)
{
    //TODO
    return 0;
}
