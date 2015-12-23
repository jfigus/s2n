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

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

int s2n_server_cert_vfy_recv(struct s2n_connection *conn)
{
    S2N_DEBUG_ENTER;

    /* Calculate master_secret since this is the last handshake
     * message prior to the finished msg. */
    GUARD(s2n_tls13_prf_master_secret(conn));

    if (conn->mode == S2N_CLIENT) {
	conn->handshake.next_state = SERVER_FINISHED;
    } else {
	conn->handshake.next_state = CLIENT_FINISHED;
    }

    return 0;
}

int s2n_server_cert_vfy_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    S2N_DEBUG_ENTER;

    //TODO: we'll send an empty message for now, need to implement this message
    GUARD(s2n_stuffer_write_uint16(out, 0));

    if (conn->mode == S2N_CLIENT) {
	conn->handshake.next_state = CLIENT_FINISHED;
    } else {
	conn->handshake.next_state = SERVER_FINISHED;
    }
 
    return 0;
}
