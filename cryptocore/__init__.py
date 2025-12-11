# src/cryptocore/__init__.py
from .hash.sha256 import SHA256, sha256, sha256_bytes
from .hash.sha3_256 import SHA3_256, sha3_256, sha3_256_bytes
from .modes.ecb import ECBCipher
from .modes.cbc import CBCCipher
from .modes.cfb import CFBCipher
from .modes.ofb import OFBCipher
from .modes.ctr import CTRCipher
from .csprng import generate_random_bytes, generate_key, generate_iv
from .file_io import read_file, write_file, read_file_with_iv, write_file_with_iv
from .cli import parse_args, validate_key, check_weak_key

__all__ = [
    'SHA256', 'sha256', 'sha256_bytes',
    'SHA3_256', 'sha3_256', 'sha3_256_bytes',
    'ECBCipher', 'CBCCipher', 'CFBCipher', 'OFBCipher', 'CTRCipher',
    'generate_random_bytes', 'generate_key', 'generate_iv',
    'read_file', 'write_file', 'read_file_with_iv', 'write_file_with_iv',
    'parse_args', 'validate_key', 'check_weak_key'
]

__version__ = '1.0.0'