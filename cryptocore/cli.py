import argparse
import sys


def parse_args():
    parser = argparse.ArgumentParser(
        description='CryptoCore - AES-128 ECB Encryptor/Decryptor',
        usage='cryptocore -algorithm aes -mode ecb -encrypt -key @001122... -input file.txt -output file.bin'
    )


    parser.add_argument('-algorithm', required=True, choices=['aes'], help='Cipher algorithm (only aes supported)')
    parser.add_argument('-mode', required=True, choices=['ecb'], help='Mode of operation (only ecb supported)')
    parser.add_argument('-key', required=True, help='Encryption key as hexadecimal string starting with @')
    parser.add_argument('-input', required=True, help='Input file path')
    parser.add_argument('-output', required=True, help='Output file path')


    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-encrypt', action='store_true', help='Encrypt mode')
    group.add_argument('-decrypt', action='store_true', help='Decrypt mode')

    return parser.parse_args()


def validate_key(key_str: str) -> bytes:
    if not key_str.startswith('@'):
        raise ValueError("Key must start with @ symbol")

    hex_key = key_str[1:]

    if len(hex_key) != 32:
        raise ValueError("Key must be 16 bytes (32 hex characters)")

    try:
        return bytes.fromhex(hex_key)
    except ValueError:
        raise ValueError("Key must be a valid hexadecimal string")