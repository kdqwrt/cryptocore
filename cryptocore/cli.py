import argparse
import sys



def validate_key(key_str: str) -> bytes:
    if not key_str.startswith('@'):
        raise ValueError("Key must start with @")

    hex_str = key_str[1:]
    if len(hex_str) != 32:
        raise ValueError("Key must be 16 bytes (32 hex characters)")

    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        raise ValueError("Key must be valid hexadecimal")


def validate_iv(iv_str: str) -> bytes:
    if not iv_str:
        return None

    if len(iv_str) != 32:
        raise ValueError("IV must be 16 bytes (32 hex characters)")

    try:
        return bytes.fromhex(iv_str)
    except ValueError:
        raise ValueError("IV must be valid hexadecimal")


def parse_args():
    parser = argparse.ArgumentParser(
        description='CryptoCore - File Encryption Tool with AES-128'
    )

    parser.add_argument('--algorithm', choices=['aes'], required=True,
                        help='Encryption algorithm (only aes supported)')
    parser.add_argument('--mode', choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'], required=True,
                        help='Block cipher mode of operation')
    parser.add_argument('--encrypt', action='store_true',
                        help='Encrypt mode')
    parser.add_argument('--decrypt', action='store_true',
                        help='Decrypt mode')
    parser.add_argument('--key', required=True,
                        help='Encryption key as @ + 32 hex chars (e.g., @00112233445566778899aabbccddeeff)')
    parser.add_argument('--input', required=True,
                        help='Input file path')
    parser.add_argument('--output', required=True,
                        help='Output file path')
    parser.add_argument('--iv',
                        help='Initialization vector as 32 hex chars (for decryption only)')

    args = parser.parse_args()

    if not (args.encrypt ^ args.decrypt):
        parser.error("Must specify either --encrypt or --decrypt")

    if args.encrypt and args.iv:
        print("Warning: IV is generated automatically for encryption. Provided IV will be ignored.",
              file=sys.stderr)
        args.iv = None

    if args.decrypt and args.mode != 'ecb' and not args.iv:
        print("Warning: No IV provided for decryption. Will read IV from input file.",
              file=sys.stderr)

    if args.mode == 'ecb' and args.iv:
        print("Warning: IV is not used in ECB mode. Provided IV will be ignored.",
              file=sys.stderr)
        args.iv = None

    return args