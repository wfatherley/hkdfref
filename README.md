# `hkdfref` - HMAC-based key derivation function
Key derivation functions (KDFs) take as input certain *initial keying material* and return certain *cryptographically strong secret keys*. Cryptographic systems require KDFs. This tool provides a reference implementation of the HMAC-based KDF described in [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) (HKDF).

<hr>

## Details
The HKDF is modular, consisting of
 
 - *extract* (the function `hkdfref.extract`)
 - and *expand* (the function `hkdfref.expand`) parts.
 
In the *extract part*, a fixed-length psuedorandom key is extracted from the *initial keying material*. The extract part aims to increase informational uniformity of the inital keying material. Scenarios where this step is helpful in particular include: when an attacker might have partial knowledge or control of these input materials. Scenarios where this step is less helpful include: the initial keying material is of sufficiently high informational uniformity. The RFC describes the extract part as optional.
 
In the *expand part*, the fixed-length pseudorandom key is exapnded into several additional pseudorandom keys. These *several additional pseudorandom keys* are the output of HKDF. The aim of this part is to ensure the output keys are suitable for a specific cyrptographic algorithm.

The differentiation of extract and expand parts is viewed in this RFC as circumventing possible shortcomings in KDF design. Further, the RFC's stated goal is to "accomodate a wide range of KDF requirements while minimizing the assumptions about the underlying hash function". The two parts can be executed together as described, using `hkdfref.hkdf`.

## Usage
A simple example:
```python
from hkdfref import hkdf


# input keying material
ikm = b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"

# some salt bytes to pass to extract
salt = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c"

# information padding bytes
info = b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9"

# desired output key material length
l = 42


# a secure cryptographic key (uses sha512)
okm = hkdf(ikm, salt=salt, info=info, l=l)
```

## Installation
Depends only on the standard library. Sources available on [GitHub](https://github.com/wfatherley/hkdfref.git) and [PyPI](). Use `pip` to install:

```python3 -m pip install hkdfref```

## References
 - Implements [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
 - See also [python-hkdf](https://github.com/casebeer/python-hkdf/tree/master)