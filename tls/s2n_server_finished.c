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

#include <stdint.h>

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

int s2n_server_finished_recv(struct s2n_connection *conn)
{
    uint8_t *our_version;
    int length = S2N_TLS_FINISHED_LEN;

    S2N_DEBUG_ENTER;

    if (conn->actual_protocol_version == S2N_TLS13) {
	/* Compute the finished message */
	GUARD(s2n_tls13_prf_finished(conn, 0));
    }
    our_version = conn->handshake.server_finished;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        length = S2N_SSL_FINISHED_LEN;
    } else if (conn->actual_protocol_version == S2N_TLS13) {
	//FIXME: this is the sha256 length, should not be hard-coded
	length = 32;
    }

    uint8_t *their_version = s2n_stuffer_raw_read(&conn->handshake.io, length);
    notnull_check(their_version);

    if (!s2n_constant_time_equals(our_version, their_version, length)) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    if (conn->actual_protocol_version == S2N_TLS13) {
	//FIXME: no client auth support yet
	conn->handshake.next_state = CLIENT_FINISHED;
    } else {
	conn->handshake.next_state = HANDSHAKE_OVER;
    }

    return 0;
}

int s2n_server_finished_send(struct s2n_connection *conn)
{
    uint8_t *our_version;
    int length = S2N_TLS_FINISHED_LEN;

    S2N_DEBUG_ENTER;

    if (conn->actual_protocol_version == S2N_TLS13) {
	/* Generate and save the master_secret before we send the finished message */
	GUARD(s2n_tls13_prf_master_secret(conn));
	/* Compute the finished message */
	GUARD(s2n_tls13_prf_finished(conn, 0));
    }

    our_version = conn->handshake.server_finished;

    if (conn->actual_protocol_version == S2N_SSLv3) {
        length = S2N_SSL_FINISHED_LEN;
    } else if (conn->actual_protocol_version == S2N_TLS13) {
	//FIXME: this is the sha256 length, should not be hard-coded
	length = 32;
    }

    GUARD(s2n_stuffer_write_bytes(&conn->handshake.io, our_version, length));

    /* For TLS 1.3, we started encrypting when sending the Encrypted Ext message */
    if (conn->actual_protocol_version < S2N_TLS13) {
	//FIXME: this will need to move once we support client auth
	GUARD(s2n_prf_client_finished(conn));

	/* Zero the sequence number */
	struct s2n_blob seq = {.data = conn->pending.server_sequence_number, .size = S2N_TLS_SEQUENCE_NUM_LEN };
	GUARD(s2n_blob_zero(&seq));

	/* Update the pending state to active, and point the client at the active state */
	memcpy_check(&conn->active, &conn->pending, sizeof(conn->active));
	conn->client = &conn->active;
	conn->handshake.next_state = HANDSHAKE_OVER;
    } else {
	conn->handshake.next_state = CLIENT_FINISHED;
    }


    return 0;
}
