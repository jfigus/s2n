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
#include <s2n.h>
#include <time.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_random.h"

//FIXME
extern int s2n_tls13_dodh(struct s2n_connection *conn);

int s2n_encrypted_ext_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    uint16_t extensions_size;

    S2N_DEBUG_ENTER;

    GUARD(s2n_stuffer_read_uint16(in, &extensions_size));

    if (extensions_size > s2n_stuffer_data_available(in)) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    struct s2n_blob extensions;
    extensions.size = extensions_size;
    extensions.data = s2n_stuffer_raw_read(in, extensions.size);

    GUARD(s2n_server_extensions_recv(conn, &extensions));

    conn->handshake.next_state = SERVER_CERT;

    return 0;
}

int s2n_encrypted_ext_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    S2N_DEBUG_ENTER;

    /* Now that ServerHello has been sent, it has been hashed and
     * we can derive key material. */
    GUARD(s2n_tls13_dodh(conn));

    GUARD(s2n_server_encrypted_extensions_send(conn, out));

    /* Zero the sequence number */
    struct s2n_blob seq = {.data = conn->pending.server_sequence_number, .size = S2N_TLS_SEQUENCE_NUM_LEN };
    GUARD(s2n_blob_zero(&seq));

    /* Update the pending state to active, and point the client at the active state */
    struct s2n_cert_chain_and_key *save_chain = conn->server->chosen_cert_chain;
    memcpy_check(&conn->active, &conn->pending, sizeof(conn->active));
    conn->client = &conn->active;
    conn->server->chosen_cert_chain = save_chain;

    conn->handshake.next_state = SERVER_CERT;

    return 0;
}
