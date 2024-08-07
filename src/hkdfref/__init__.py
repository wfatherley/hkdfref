"""hkdfref"""
import argparse
import codecs
import hashlib

from sys import stdout

from ._hkdfref import (
    default_hash, default_salt, expand, extract, hkdf, logger
)


def cli() -> None:
    """return None"""
    logger.debug("cli: enter")

    # configure argument parser
    argument_parser = argparse.ArgumentParser(
        prog="hkdf",
        description="Generate secure keying material according to RFC 5869.",
        epilog="Specification: https://datatracker.ietf.org/doc/html/rfc5869",
    )
    argument_parser.add_argument(
        "ikm",
        type=lambda string: string.encode("latin-1"),
        action="append",
        help="Input key material. Fed into HKDF as UTF-8 bytes."
    )
    argument_parser.add_argument(
        "-s",
        "--salt",
        type=lambda string: string.encode("latin-1"),
        default=default_salt,
        help=(
            "Salt for extract step. Defaults to 0x00 * 20. Fed into HKDF as"
            " UTF-8 bytes."
        )
    )
    argument_parser.add_argument(
        "--hash",
        help="One of the known SHAs. Used by both extract and expand"
    )
    argument_parser.add_argument(
        "--exthash",
        help="One of the known SHAs. Used only by extract."
    )
    argument_parser.add_argument(
        "--exphash",
        help="One of the known SHAs. Used only by expand."
    )
    argument_parser.add_argument(
        "-i",
        "--info",
        default=b"",
        type=lambda string: string.encode("latin-1"),
        help="Info for expand step. Fed into HKDF as UTF-8 bytes."
    )
    output_length_group = argument_parser.add_mutually_exclusive_group(required=True)
    output_length_group.add_argument(
        "-l",
        "--length",
        type=int,
        help="First octets to return. Return whole without."
    )
    output_length_group.add_argument(
        "--returnall", action="store_true", help="Return entire result"
    )
    argument_parser.add_argument(
        "--skipextract", action="store_true", help="Skip extract step"
    )

    # parse arguments
    namespace = argument_parser.parse_args()
    logger.debug("cli: args=%s", namespace)
    
    # rebind hash functions
    namespace.hash = namespace.hash or default_hash
    namespace.exthash = getattr(hashlib, str(namespace.exthash), default_hash)
    namespace.exphash = getattr(hashlib, str(namespace.exphash), default_hash)
    
    # return okm
    stdout.write(
        codecs.encode(
            hkdf(
                *namespace.ikm,
                salt=namespace.salt,
                l=namespace.length,
                info=namespace.info,
                extract_hash=namespace.exthash,
                expand_hash=namespace.exphash,
                hash=namespace.hash,
                skip_extract=namespace.skipextract,
                return_all=namespace.returnall
            ),
            "hex_codec"
        ).decode()
    )
