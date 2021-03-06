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

#include <s2n.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

int s2n_server_cert_recv(struct s2n_connection *conn)
{
    uint32_t size_of_all_certificates;

    S2N_DEBUG_ENTER;

    GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, &size_of_all_certificates));

    if (size_of_all_certificates > s2n_stuffer_data_available(&conn->handshake.io) || size_of_all_certificates < 3) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    int certificate_count = 0;
    while (s2n_stuffer_data_available(&conn->handshake.io)) {
        uint32_t certificate_size;

        GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, &certificate_size));

        if (certificate_size > s2n_stuffer_data_available(&conn->handshake.io) || certificate_size == 0) {
            S2N_ERROR(S2N_ERR_BAD_MESSAGE);
        }

        struct s2n_blob asn1cert;
        asn1cert.data = s2n_stuffer_raw_read(&conn->handshake.io, certificate_size);
        asn1cert.size = certificate_size;
        notnull_check(asn1cert.data);

        /* TODO: certificate validation goes here */
        gt_check(certificate_size, 0);

        /* Pull the public key from the first certificate */
        if (certificate_count == 0) {
            GUARD(s2n_asn1der_to_rsa_public_key(&conn->pending.server_rsa_public_key, &asn1cert));
        }

        certificate_count++;
    }

    gte_check(certificate_count, 1);

    if (conn->actual_protocol_version == S2N_TLS13) {
	//FIXME: no client auth support yet
	conn->handshake.next_state = SERVER_CERT_VERIFY;
    } else {
	conn->handshake.next_state = SERVER_HELLO_DONE;

	if (conn->status_type == S2N_STATUS_REQUEST_OCSP) {
	    conn->handshake.next_state = SERVER_CERT_STATUS;
	} else if (conn->pending.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_EPH) {
	    conn->handshake.next_state = SERVER_KEY;
	}
    }

    return 0;
}

int s2n_server_cert_send(struct s2n_connection *conn)
{
    struct s2n_cert_chain *head = conn->server->chosen_cert_chain->head;

    S2N_DEBUG_ENTER;

    GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, conn->server->chosen_cert_chain->chain_size));

    while (head) {
        GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, head->cert.size));
        GUARD(s2n_stuffer_write_bytes(&conn->handshake.io, head->cert.data, head->cert.size));
        head = head->next;
    }

    if (conn->actual_protocol_version == S2N_TLS13) {
	//FIXME: no client auth support yet
	conn->handshake.next_state = SERVER_CERT_VERIFY;
    } else {
	conn->handshake.next_state = SERVER_HELLO_DONE;

	if (s2n_server_can_send_ocsp(conn)) {
	    conn->handshake.next_state = SERVER_CERT_STATUS;
	} else if (conn->pending.cipher_suite->key_exchange_alg->flags & S2N_KEY_EXCHANGE_EPH) {
	    conn->handshake.next_state = SERVER_KEY;
	}
    }

    return 0;
}
