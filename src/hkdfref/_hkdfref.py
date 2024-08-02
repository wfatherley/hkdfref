"""_hkdfref"""
import hashlib
import hmac

from logging import getLogger
from math import ceil
from typing import Any, Callable


logger = getLogger(__name__)


default_hash = hashlib.sha512
default_hashlen = default_hash().digest_size

default_salt = default_hashlen * bytearray((0,))
default_hmac_hash = hmac.new(default_salt, digestmod=default_hash)


def hkdf(*ikm: bytes, **kwargs: Any) -> bytes:
    """return bytes"""
    logger.debug("hkdf: kwargs=%s", kwargs)

    # gather extract parameters
    salt = kwargs.get("salt", default_salt)
    extract_hash = kwargs.get(
        "extract_hash", kwargs.get("hash", default_hash)
    )

    # gather expand parameters
    info = kwargs.get("info", b"")
    l = kwargs.get("l", 255 * default_hashlen)
    expand_hash = kwargs.get(
        "expand_hash", kwargs.get("hash", default_hash)
    )

    # optionally skip extract step
    if not kwargs.get("skip_extract"):
        prk = extract(salt, *ikm, hash=extract_hash)
    else:
        prk = b"".join(ikm)
    return expand(prk, info, l, expand_hash)


def expand(
    prk: bytes,
    info: bytes,
    l: int,
    hash: Callable=default_hash,
    return_all: bool=False
) -> tuple:
    """return tuple"""
    logger.debug("expand: enter")

    # obtain digest size from hash
    try:
        digest_size = hash().digest_size
    except:
        logger.exception("expand: hash not from hashlib")
        if not hasattr(hash, digest_size):
            raise
        digest_size = hash.digest_size

    # raise if l is too big
    if l > 255 * digest_size:
        logger.exception("expand: l=%i, digest_size=%i", l, digest_size)
        raise ValueError("l is too big (%i)" % l)

    # run digest loop with hmac.digest as hmac-hash
    t, t_n = b"", b""
    for n in range(1, ceil(l / digest_size) + 1):
        logger.debug("expand: n=%i, digest=%s", n, t)
        t_n = hmac.digest(prk, t_n + info + bytearray((n,)), digest=hash)
        t += t_n
    
    # return okm
    if return_all:
        return t
    return t[:l]


def extract(salt: bytes, *ikm: bytes, hash: Callable=default_hash) -> bytes:
    """return bytes"""
    logger.debug("extract: salt=%s, ikm=%s", salt, ikm)

    # raise if no input key material
    if not ikm:
        logger.exception("extract: no input key material")
        raise ValueError("no input key material")

    # instantiate hmac-hash
    if hash == default_hash and salt == default_salt:
        hmac_hash = default_hmac_hash
    else:
        hmac_hash = hmac.new(salt, digestmod=hash)

    # update hmac-hash and return digest
    hmac_hash.update(b"".join(ikm))
    return hmac_hash.digest()
