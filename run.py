import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from cryptocore.cli import parse_args, validate_key, validate_iv
from cryptocore.file_io import read_file, write_file, read_file_with_iv, write_file_with_iv
from cryptocore.modes.ecb import ECBCipher
from cryptocore.modes.cbc import CBCCipher
from cryptocore.modes.cfb import CFBCipher
from cryptocore.modes.ctr import CTRCipher
from cryptocore.modes.ofb import OFBCipher
from cryptocore.csprng import generate_iv,generate_key


MODE_CLASSES = {
    'ecb': ECBCipher,
    'cbc': CBCCipher,
    'cfb': CFBCipher,
    'ofb': OFBCipher,
    'ctr': CTRCipher
}


def encrypt_data(args, key):
    cipher_class = MODE_CLASSES[args.mode]
    plaintext = read_file(args.input)

    if args.mode == 'ecb':
        cipher = cipher_class(key)
        ciphertext = cipher.encrypt(plaintext)
        write_file(args.output, ciphertext)
        return None
    else:
        cipher = cipher_class(key)
        ciphertext = cipher.encrypt(plaintext)
        write_file_with_iv(args.output, cipher.iv, ciphertext)
        return cipher.iv


def decrypt_data(args, key, iv):
    cipher_class = MODE_CLASSES[args.mode]

    if args.mode == 'ecb':
        ciphertext = read_file(args.input)
        cipher = cipher_class(key)
        plaintext = cipher.decrypt(ciphertext)
        write_file(args.output, plaintext)
        return plaintext
    else:
        if iv is None:
            file_iv, ciphertext = read_file_with_iv(args.input)
            cipher = cipher_class(key, file_iv)
        else:
            all_data = read_file(args.input)
            if len(all_data) < 16:
                raise ValueError("File is too short to contain IV (less than 16 bytes)")

            ciphertext = all_data[16:]
            cipher = cipher_class(key, iv)

        plaintext = cipher.decrypt(ciphertext)
        write_file(args.output, plaintext)
        return plaintext


def main():
    try:
        args = parse_args()

        if args.encrypt and not args.key:
            generated_key = generate_key()
            key_hex = generated_key.hex()
            print(f"[INFO] Generated random key: {key_hex}")
            key = generated_key
        else:
            key = validate_key(args.key)


        iv = validate_iv(args.iv) if args.iv else None
        print(f"Processing {args.input} -> {args.output} using {args.mode.upper()} mode...")

        if args.encrypt and args.iv and args.mode != 'ecb':
            print("Warning: IV is generated automatically for encryption. Provided IV will be ignored.")
            iv = None

        #if args.decrypt and args.mode != 'ecb' and not args.iv:
         #   print("Warning: No IV provided for decryption. Will read IV from input file.")

        if args.encrypt:
            generated_iv = encrypt_data(args, key)
            if generated_iv:
                print(f"Encryption successful! IV (hex): {generated_iv.hex()}")
                print(f"IV has been written to the beginning of {args.output}")
            else:
                print("Encryption successful!")

        elif args.decrypt:
            decrypted_data = decrypt_data(args, key, iv)
            print(f"Decryption successful! Decrypted {len(decrypted_data)} bytes.")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()