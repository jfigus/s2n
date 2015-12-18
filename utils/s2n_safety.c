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

#define _GNU_SOURCE             /* For syscall on Linux */
#undef _POSIX_C_SOURCE          /* For syscall() on Mac OS X */

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include "error/s2n_errno.h"
/**
 * Get the process id
 *
 * Returns:
 *  The process ID of the current process
 */
pid_t s2n_actual_getpid()
{
#if defined(__GNUC__) && defined(SYS_getpid)
    /* http://yarchive.net/comp/linux/getpid_caching.html */
    return (pid_t) syscall(SYS_getpid);
#else
    return getpid();
#endif
}

int s2n_constant_time_equals(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint8_t xor = 0;
    for (int i = 0; i < len; i++) {
        xor |= a[i] ^ b[i];
    }

    return !xor;
}

int s2n_constant_time_copy_or_dont(uint8_t *a, const uint8_t *b, uint32_t len, uint8_t dont)
{
    uint8_t mask = ~(0xff << ((!!dont) * 8));

    /* dont = 0 : mask = 0x00 */
    /* dont > 0 : mask = 0xff */

    for (int i = 0; i < len; i++) {
        a[i] &= mask;
        a[i] |= b[i] & ~mask;
    }

    return 0;
}


//FIXME: putting this here for now, for lack of a better place to
//       put this.  As I learn more about s2n, hopefully a better
//       home for debug logic will present itself.
void s2n_debug_dumphex(const char *label, uint8_t *data, uint16_t len)
{
#ifdef S2N_DEBUG_FLOOD
    int i;

    printf("%s", label);
    for (i=0; i<len; i++) {
	printf("%02x ", data[i]);
    }
    printf("\n");
#endif
}

