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
#pragma once

#include <stdint.h>
#include "utils/s2n_blob.h"
#include "crypto/s2n_hmac.h"

extern int s2n_hkdf_get_hmac_size(s2n_hmac_algorithm alg);
extern int s2n_hkdf_extract(s2n_hmac_algorithm alg, struct s2n_blob *salt, struct s2n_blob *key, struct s2n_blob *prk);
extern int s2n_hkdf_expand(s2n_hmac_algorithm alg, struct s2n_blob *prk, struct s2n_blob *info, uint8_t L, struct s2n_blob *okm);
extern int s2n_hkdf_expand_label(s2n_hmac_algorithm alg, struct s2n_blob *secret, struct s2n_blob *label, 
	                         struct s2n_blob *hash, uint8_t L, struct s2n_blob *result);

