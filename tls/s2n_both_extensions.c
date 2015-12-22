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
#include <string.h>

#include "error/s2n_errno.h"

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_connection.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include <openssl/ec.h>
#include <openssl/ecdh.h>

int s2n_keyshare_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    uint8_t point_len;
    struct s2n_blob point;
    struct s2n_ecc_params *ks;

    S2N_DEBUG_ENTER;

    if (conn->mode == S2N_CLIENT) {
	ks = &conn->pending.ckeyshare_ecc_params;
    } else {
	ks = &conn->pending.skeyshare_ecc_params;
    }

    GUARD(s2n_ecc_calculate_point_length(EC_KEY_get0_public_key(ks->ec_key), 
	                                 EC_KEY_get0_group(ks->ec_key), &point_len));


    GUARD(s2n_stuffer_write_uint16(out, TLS_EXTENSION_KEYSHARE));
    GUARD(s2n_stuffer_write_uint16(out, point_len+4));
    GUARD(s2n_stuffer_write_uint16(out, ks->negotiated_curve->iana_id));
    GUARD(s2n_stuffer_write_uint16(out, point_len));

    /* Write the point */
    point.data = s2n_stuffer_raw_write(out, point_len);
    point.size = point_len;
    notnull_check(point.data);
    GUARD(s2n_ecc_write_point_data_snug(EC_KEY_get0_public_key(ks->ec_key), 
		                        EC_KEY_get0_group(ks->ec_key), &point));
    s2n_debug_dumphex("Sending key: ", point.data, point.size);

    return 0;
}

int s2n_keyshare_rcv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    EC_POINT *point;
    struct s2n_blob point_blob;
    uint16_t curve_id;
    uint16_t point_len;
    struct s2n_ecc_params *peer_ks;

    S2N_DEBUG_ENTER;

    GUARD(s2n_stuffer_read_uint16(extension, &curve_id));
    GUARD(s2n_stuffer_read_uint16(extension, &point_len));
    if (point_len > s2n_stuffer_data_available(extension) || point_len < 5) {
        /* Malformed length, ignore the extension */
        return 0;
    }

    //printf("len=%d curve_id=%d\n", point_len, curve_id);

    if (conn->mode == S2N_CLIENT) {
	peer_ks = &conn->pending.skeyshare_ecc_params;
    } else {
	peer_ks = &conn->pending.ckeyshare_ecc_params;
    }

    if (peer_ks->ec_key) {
	EC_KEY_free(peer_ks->ec_key);
    }
    //FIXME - need to use the parsed curve_id
    peer_ks->ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    /* Read the point */
    point_blob.size = point_len;
    point_blob.data = s2n_stuffer_raw_read(extension, point_blob.size);
    notnull_check(point_blob.data);

    s2n_debug_dumphex("Recvd keyshare: ", point_blob.data, point_len);

    /* Parse and store the client public point */
    point = s2n_ecc_blob_to_point(&point_blob, peer_ks->ec_key);
    if (point == NULL) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }
    if (EC_KEY_set_public_key(peer_ks->ec_key, point) != 1) {
        EC_POINT_free(point);
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }
    EC_POINT_free(point);

    if (conn->mode == S2N_SERVER) {
	//FIXME - hardcoded to prime256v1
	conn->pending.skeyshare_ecc_params.negotiated_curve = &s2n_ecc_supported_curves[0];
	GUARD(s2n_ecc_generate_ephemeral_key(&conn->pending.skeyshare_ecc_params));
    }

    return 0;
}

//FIXME: need to fit this into the proper location
// This routine expects cipher suite to have already been
// selected and server random to have been generated.
// So invoke this when processing ServerHello on either side.
int s2n_tls13_dodh(struct s2n_connection *conn)
{
    struct s2n_blob shared_key;
    EC_KEY *my_key;
    struct s2n_ecc_params *peer_ks;

    if (conn->mode == S2N_CLIENT) {
	peer_ks = &conn->pending.skeyshare_ecc_params;
	my_key = (&conn->pending.ckeyshare_ecc_params)->ec_key;
    } else {
	peer_ks = &conn->pending.ckeyshare_ecc_params;
	my_key = (&conn->pending.skeyshare_ecc_params)->ec_key;
    }

    if (s2n_ecc_compute_shared_secret(my_key, EC_KEY_get0_public_key(peer_ks->ec_key), &shared_key)) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
	return -1;
    }

    s2n_debug_dumphex("secret: ", shared_key.data, shared_key.size);

    /* Turn the pre-master secret into a master secret and
     * derive the key material for the session */
    GUARD(s2n_tls13_handshake_key_expansion(conn, &shared_key));

    /*
     * It's too early to calculate the master_secret since not all
     * the handshake messages have been hashed.  We'll need to
     * save the pre_master_secret for later when it's time
     * to calculate the master_secret.
     */
    if (shared_key.size <= S2N_TLS_SECRET_LEN) {
	s2n_debug_dumphex("ephemeral key: ", shared_key.data, shared_key.size);
	memcpy(conn->pending.pre_master_secret, shared_key.data, shared_key.size);
	conn->pending.pre_master_secret_len = shared_key.size;
    } else {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
	return -1;
    }

    /* Erase the pre-master secret */
    GUARD(s2n_blob_zero(&shared_key));
    GUARD(s2n_free(&shared_key));

    return 0;
}

