import sys
import os


sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from .cli import parse_args, validate_key
from .file_io import read_file, write_file
from .modes.ecb import encrypt_ecb, decrypt_ecb


def main():
    try:
        args = parse_args()

        key = validate_key(args.key)

        input_data = read_file(args.input)

        if args.encrypt:
            output_data = encrypt_ecb(input_data, key)
            print(f"Encryption successful: {args.input} → {args.output}")
        else:
            output_data = decrypt_ecb(input_data, key)
            print(f"Decryption successful: {args.input} → {args.output}")

        write_file(args.output, output_data)

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()