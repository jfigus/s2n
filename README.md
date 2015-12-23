## What is this repo?

This repo is a fork of the Amazon S2N TLS stack.  This fork will include support
for TLS 1.3 as defined in [draft-ietf-tls-tls13-10].  This code is being developed
as an academic exercise.  This code is not intended for commercial use, has not
been through the appropriate security reviews and is for experimentation only.

The goal of this fork is to better understand the hurdles for implementating TLS 1.3,
along with providing feedback to the IETF TLS WG as needed.  This code is a work-in-progress,
as the TLS 1.3 draft has not been ratified.  Further revisions to the TLS 1.3 draft
are anticipated.  It is my hope to update this code as the draft is revised in the future.

The S2N stack was chosen for this exercise because of it's simplicity.  While my
experience with TLS is limited to the OpenSSL stack, the state machine implementation
within OpenSSL doesn't lend itself well for the TLS 1.3 state machine changes.  The
S2N stack appears to be a clean room implementation of TLS, supporting up through TLS 1.2.
S2N implements a more structured state machine than OpenSSL.  Having said that, S2N is
not without shortcomings.  S2N does not provide sufficient TLS client side capabilities
for commericial use.  For instance, S2N does not verify the server certificate during
a TLS handshake.  S2N has minimal support for TLS extensions.  S2N does not support
ECDSA certificates.  There are probably other shortcomings that I'm failing to mention.
However, for the purposes of this exercise, S2N is easier to extend for TLS 1.3 than
OpenSSL. 

## Project status

The initial goal of this exercise is to provide support for a 1-RTT handshake.  The
following TLS 1.3 requirements have been implemented:

* KeyShare extension is handled in both Client and Server hello messages
* EncryptedExtensions message has been implemented
* HKDF is implemented per RFC5869 to generate xES and master_secret
* ECDHE key exchange is working (limited to prime256v1 curve)
* Handshake key expansion using xES is working
* Application key expansion using master_secret
* Obsolete messages removed from handshake (e.g. ServerKeyExchange)
* Both server and client Finished messages need proper hash calculation

The following items remain to fully implement 1-RTT:

* Server CertificateVerify message not implemented
* HelloRetryRequest message not implemented
* ServerConfiguration message not implemented
* Hash selection is not derived from negotiated cipher suite
* DH key exchange is not implemented in KeyShare extension
* Need to review record layer changes and implement

## How to use this fork 

To use this code, follow the S2N build instructions.  However, only the OpenSSL crypto layer is supported
in this fork.  S2N has abstracted the crypto layer, allowing OpenSSL or another library to be used
for crypto support.  I have not fully honored this abstraction layer in this fork.  Therefore,
you will need to use OpenSSL for crypto support with S2N.  
The code in this fork was developed on a Ubuntu 14 system (64-bit).  You'll need the OpenSSL devel
package installed.
Once S2N is compiled and LD_LIBRARY_PATH has been setup, use s2nc and s2nd to setup a TLS 1.3 session.
You'll need to set S2N_ENABLE_CLIENT_MODE=1 on the client side.  By default S2N disables client side
support, probably because there's no logic to actually verify the server certificate.  Using two
terminal windows, run both of the following commands:

```c
s2nd localhost 8443

s2nc localhost 8443
```


The original S2N readme follows...

<img src="docs/images/s2n_logo_github.png" alt="s2n">

s2n is a C99 implementation of the TLS/SSL protocols that is designed to be simple, small, fast, and with security as a priority. It is released and licensed under the Apache Software License 2.0. 

[![Build Status](https://img.shields.io/travis/awslabs/s2n.svg)](https://travis-ci.org/aws/s2n)
[![Apache 2 License](https://img.shields.io/github/license/awslabs/s2n.svg)](http://aws.amazon.com/apache-2-0/)
[![C99](https://img.shields.io/badge/language-C99-blue.svg)](http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1256.pdf)
[![Github forks](https://img.shields.io/github/forks/awslabs/s2n.svg)](https://github.com/awslabs/s2n/network)
[![Github stars](https://img.shields.io/github/stars/awslabs/s2n.svg)](https://github.com/awslabs/s2n/stargazers)

## Using s2n

The s2n I/O APIs are designed to be intuitive to developers familiar with the widely-used POSIX I/O APIs, and s2n supports blocking, non-blocking, and full-duplex I/O. Additionally there are no locks or mutexes within s2n. 

```c
/* Create a server mode connection handle */
struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
if (conn == NULL) {
    ... error ...
}

/* Associate a connection with a file descriptor */
if (s2n_connection_set_fd(conn, fd) < 0) {
    ... error ...
}

/* Negotiate the TLS handshake */
s2n_blocked_status blocked;
if (s2n_negotiate(conn, &blocked) < 0) {
    ... error ...
}
    
/* Write data to the connection */
int bytes_written;
bytes_written = s2n_send(conn, "Hello World", sizeof("Hello World"), &blocked);
```

For details on building the s2n library and how to use s2n in an application you are developing, see the [API Reference](https://github.com/awslabs/s2n/blob/master/docs/USAGE-GUIDE.md).

## s2n features

s2n implements SSLv3, TLS1.0, TLS1.1, and TLS1.2. For encryption, s2n supports 128-bit and 256-bit AES, in the CBC and GCM modes, 3DES, and RC4. For forward secrecy, s2n supports both DHE and ECDHE. s2n also supports the Server Name Indicator (SNI), Application-Layer Protocol Negotiation (ALPN) and the Online Certificate Status Protocol (OCSP) TLS extensions. SSLv3, RC4, and DHE are each disabled by default for security reasons. 

As it can be difficult to keep track of which encryption algorithms and protocols are best to use, s2n features a simple API to use the latest "default" set of preferences. If you prefer to remain on a specific version for backwards compatibility, that is also supported. 

```c
/* Use the latest s2n "default" set of ciphersuite and protocol preferences */
s2n_config_set_cipher_preferences(config, "default");

/* Use a specific set of preferences, update when you're ready */
s2n_config_set_cipher_preferences(config, "20150306")
```

## s2n safety mechanisms

Internally s2n takes a systematic approach to data protection and includes several mechanisms designed to improve safety.

##### Small and auditable code base
Ignoring tests, blank lines and comments, s2n is about 6,000 lines of code. s2n's code is also structured and written with a focus on reviewability. All s2n code is subject to code review, and we plan to complete security evaluations of s2n on an annual basis.

To date there have been two external code-level reviews of s2n, including one by a commercial security vendor. s2n has also been shared with some trusted members of the broader cryptography, security, and Open Source communities. Any issues discovered are always recorded in the s2n issue tracker. 

##### Static analysis, fuzz-testing and penetration testing

In addition to code reviews, s2n is subject to regular static analysis, fuzz-testing, and penetration testing. Several penetration tests have occurred, including two by commercial vendors.  

##### Unit tests and end-to-end testing

s2n includes positive and negative unit tests and end-to-end test cases. 

##### Erase on read
s2n encrypts or erases plaintext data as quickly as possible. For example, decrypted data buffers are erased as they are read by the application.

##### Built-in memory protection
s2n uses operating system features to protect data from being swapped to disk or appearing in core dumps.

##### Minimalist feature adoption
s2n avoids implementing rarely used options and extensions, as well as features with a history of triggering protocol-level vulnerabilities. For example there is no support for session renegotiation or DTLS.

##### Compartmentalized random number generation
The security of TLS and its associated encryption algorithms depends upon secure random number generation. s2n provides every thread with two separate random number generators. One for "public" randomly generated data that may appear in the clear, and one for "private" data that should remain secret. This approach lessens the risk of potential predictability weaknesses in random number generation algorithms from leaking information across contexts. 

##### Modularized encryption
s2n has been structured so that different encryption libraries may be used. Today s2n supports OpenSSL, LibreSSL, BoringSSL, and the Apple Common Crypto framework to perform the underlying cryptographic operations.

##### Timing blinding
s2n includes structured support for blinding time-based side-channels that may leak sensitive data. For example, if s2n fails to parse a TLS record or handshake message, s2n will add a randomized delay of between 1ms and 10 seconds, granular to nanoseconds, before responding. This raises the complexity of real-world timing side-channel attacks by a factor of at least tens of trillions. 

##### Table based state-machines
s2n uses simple tables to drive the TLS/SSL state machines, making it difficult for invalid out-of-order states to arise. 

##### C safety
s2n is written in C, but makes light use of standard C library functions and wraps all memory handling, string handling, and serialization in systematic boundary-enforcing checks. 

## Security issue notifications
If you discover a potential security issue in s2n we ask that you notify
AWS Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue. 

If you package or distribute s2n, or use s2n as part of a large multi-user service, you may be eligible for pre-notification of future s2n releases. Please contact s2n-pre-notification@amazon.com.  

## Contributing to s2n
If you are interested in contributing to s2n, please see our [development guide](https://github.com/awslabs/s2n/blob/master/docs/DEVELOPMENT-GUIDE.md).

## Language Bindings for s2n
See our [language bindings list](https://github.com/awslabs/s2n/blob/master/docs/BINDINGS.md) for language bindings for s2n that we're aware of. 
