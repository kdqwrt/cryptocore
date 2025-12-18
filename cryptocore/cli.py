import argparse
import sys
import os

# Импорты hash модулей
try:
    from .hash.sha256 import SHA256
    from .hash.sha3_256 import SHA3_256

    HAS_HASH_MODULES = True
except ImportError as e:
    print(f"Warning: Hash modules not found: {e}", file=sys.stderr)
    HAS_HASH_MODULES = False

# Импорты encryption модулей
try:
    from .modes.cbc import CBCCipher
    from .modes.cfb import CFBCipher
    from .modes.ctr import CTRCipher
    from .modes.ecb import ECBCipher
    from .modes.ofb import OFBCipher

    HAS_ENCRYPTION_MODULES = True
except ImportError as e:
    print(f"Warning: Encryption modules not found: {e}", file=sys.stderr)
    HAS_ENCRYPTION_MODULES = False

# Импорты GCM модуля
try:
    from .modes.gcm import GCM, AuthenticationError

    HAS_GCM = True
except ImportError as e:
    HAS_GCM = False


    class AuthenticationError(Exception):
        pass

# Импорты MAC (HMAC) модулей
try:
    from .mac.hmac import HMAC, StreamingHMAC

    HAS_MAC_MODULES = True
except ImportError as e:
    print(f"Warning: MAC modules not found: {e}", file=sys.stderr)
    HAS_MAC_MODULES = False

# Импорты CSPRNG
try:
    from .csprng import generate_random_bytes

    HAS_CSPRNG = True
except ImportError as e:
    print(f"Warning: CSPRNG module not found: {e}", file=sys.stderr)
    HAS_CSPRNG = False
    import os as os_module

    generate_random_bytes = os_module.urandom

# Импорты File IO
try:
    from .file_io import (
        read_file, write_file, read_file_with_iv, write_file_with_iv,
        read_file_chunks, read_gcm_file, write_gcm_file, safe_write_file,
        delete_file_if_exists
    )

    HAS_FILE_IO = True
except ImportError as e:
    print(f"Warning: File IO module not found: {e}", file=sys.stderr)
    HAS_FILE_IO = False


def validate_key(key_str: str) -> bytes:
    """Валидация ключа шифрования."""
    if not key_str:
        return None

    if not key_str.startswith('@'):
        raise ValueError("Key must start with @")

    hex_str = key_str[1:]
    if len(hex_str) != 32:
        raise ValueError("Key must be 16 bytes (32 hex characters)")

    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        raise ValueError("Key must be valid hexadecimal")


def parse_hmac_key(key_str: str) -> bytes:
    """Парсинг ключа HMAC."""
    if not key_str:
        raise ValueError("Key cannot be empty")

    try:
        if key_str.startswith('@'):
            key_str = key_str[1:]

        return bytes.fromhex(key_str)
    except ValueError:
        raise ValueError("Key must be valid hexadecimal")


def check_weak_key(key_bytes: bytes) -> bool:
    """Проверка ключа на слабость."""
    if not key_bytes:
        return False

    if all(byte == 0 for byte in key_bytes):
        return True

    sequential_up = all(key_bytes[i] == i for i in range(len(key_bytes)))
    sequential_down = all(key_bytes[i] == (255 - i) for i in range(len(key_bytes)))

    return sequential_up or sequential_down


def read_hmac_file(filename: str) -> str:
    """Чтение HMAC из файла."""
    try:
        with open(filename, 'r') as f:
            content = f.read().strip()

        if not content:
            raise ValueError("HMAC file is empty")

        lines = content.splitlines()

        for line in lines:
            words = line.strip().split()

            for word in words:
                word = word.strip()

                if (len(word) == 64 and
                        all(c in '0123456789abcdefABCDEF' for c in word)):
                    return word.lower()

        if lines:
            first_word = lines[0].strip().split()[0] if lines[0].strip() else ''
            if (len(first_word) == 64 and
                    all(c in '0123456789abcdefABCDEF' for c in first_word)):
                return first_word.lower()

        raise ValueError(f"No valid HMAC found in file {filename}")

    except FileNotFoundError:
        raise ValueError(f"HMAC file '{filename}' not found")
    except Exception as e:
        raise ValueError(f"Failed to read HMAC file: {e}")


def get_cipher_instance(mode: str, key: bytes, iv: bytes = None, aad: bytes = None):
    """Создание экземпляра шифра в зависимости от режима."""
    if mode == 'ecb':
        return ECBCipher(key)
    elif mode == 'cbc':
        return CBCCipher(key, iv)
    elif mode == 'cfb':
        return CFBCipher(key, iv)
    elif mode == 'ofb':
        return OFBCipher(key, iv)
    elif mode == 'ctr':
        return CTRCipher(key, iv)
    elif mode == 'gcm':
        if not HAS_GCM:
            raise ValueError("GCM mode is not available")
        # Для GCM iv используется как nonce
        return GCM(key, iv)
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def hmac_command(args):
    """Обработка команды HMAC."""
    if not HAS_MAC_MODULES:
        print("Error: MAC modules are not available", file=sys.stderr)
        return 1

    if not args.key:
        print("Error: --key is required for HMAC operations", file=sys.stderr)
        return 1

    if args.input != '-' and not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found", file=sys.stderr)
        return 1

    try:
        # Парсим ключ
        key_bytes = parse_hmac_key(args.key)

        # Проверяем ключ на слабость
        if check_weak_key(key_bytes):
            if not args.quiet:
                print("Warning: The provided key appears to be weak. Consider using a randomly generated key.",
                      file=sys.stderr)

        # Создаём HMAC
        hmac = StreamingHMAC(key_bytes, args.algorithm)

        # Обрабатываем входные данные
        if args.input == '-':
            while True:
                chunk = sys.stdin.buffer.read(8192)
                if not chunk:
                    break
                hmac.update(chunk)
        else:
            if HAS_FILE_IO:
                for chunk in read_file_chunks(args.input, chunk_size=8192):
                    hmac.update(chunk)
            else:
                with open(args.input, 'rb') as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        hmac.update(chunk)

        # Получаем HMAC
        computed_hmac = hmac.hexdigest()

        # Проверка, если требуется
        if args.verify:
            try:
                expected_hmac = read_hmac_file(args.verify)

                if computed_hmac == expected_hmac:
                    if not args.quiet:
                        print(f"[OK] HMAC verification successful for {args.input}", file=sys.stderr)
                    return 0
                else:
                    print(f"[ERROR] HMAC verification failed for {args.input}", file=sys.stderr)
                    if not args.quiet:
                        print(f"Computed: {computed_hmac}", file=sys.stderr)
                        print(f"Expected: {expected_hmac}", file=sys.stderr)
                    return 1
            except ValueError as e:
                print(f"Error reading verification file: {e}", file=sys.stderr)
                return 1

        # Формируем вывод
        output_line = f"{computed_hmac} {args.input}" if args.input != '-' else computed_hmac

        # Запись в файл или вывод
        if args.output:
            try:
                if args.binary:
                    if HAS_FILE_IO:
                        write_file(args.output, hmac.digest())
                    else:
                        with open(args.output, 'wb') as out_file:
                            out_file.write(hmac.digest())
                else:
                    output_text = output_line + '\n'
                    if HAS_FILE_IO:
                        write_file(args.output, output_text.encode('utf-8'))
                    else:
                        with open(args.output, 'w') as out_file:
                            out_file.write(output_text)

                if not args.quiet:
                    print(f"HMAC written to: {args.output}", file=sys.stderr)
            except IOError as e:
                print(f"Error writing to output file: {e}", file=sys.stderr)
                return 1
            except PermissionError as e:
                print(f"Error: Permission denied for output file '{args.output}': {e}", file=sys.stderr)
                return 1
        else:
            if args.binary:
                sys.stdout.buffer.write(hmac.digest())
            else:
                print(output_line)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except PermissionError as e:
        print(f"Error: Permission denied for file '{args.input}': {e}", file=sys.stderr)
        return 1
    except IOError as e:
        print(f"Error reading file '{args.input}': {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error during HMAC computation: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    return 0


def dgst_command(args):
    """Обработка команды хеширования."""
    if args.hmac:
        return hmac_command(args)

    if not HAS_HASH_MODULES:
        print("Error: Hash modules are not available", file=sys.stderr)
        return 1

    algorithms = {
        'sha256': SHA256,
        'sha3-256': SHA3_256
    }

    if args.algorithm not in algorithms:
        print(f"Error: Unsupported algorithm '{args.algorithm}'", file=sys.stderr)
        print(f"Available algorithms: {', '.join(algorithms.keys())}", file=sys.stderr)
        return 1

    if args.input != '-' and not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found", file=sys.stderr)
        return 1

    if args.input != '-' and not os.path.isfile(args.input):
        print(f"Error: '{args.input}' is not a file", file=sys.stderr)
        return 1

    try:
        hasher_class = algorithms[args.algorithm]
        hasher = hasher_class()

        if args.input == '-':
            while True:
                chunk = sys.stdin.buffer.read(8192)
                if not chunk:
                    break
                hasher.update(chunk)
            output_line = hasher.hexdigest()
        else:
            if HAS_FILE_IO:
                for chunk in read_file_chunks(args.input, chunk_size=8192):
                    hasher.update(chunk)
            else:
                with open(args.input, 'rb') as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        hasher.update(chunk)

            output_line = f"{hasher.hexdigest()} {args.input}"

        # Обработка вывода
        if args.output:
            try:
                if args.binary:
                    if HAS_FILE_IO:
                        write_file(args.output, hasher.digest())
                    else:
                        with open(args.output, 'wb') as out_file:
                            out_file.write(hasher.digest())
                else:
                    output_text = output_line + '\n'
                    if HAS_FILE_IO:
                        write_file(args.output, output_text.encode('utf-8'))
                    else:
                        with open(args.output, 'w') as out_file:
                            out_file.write(output_text)

                if not args.quiet:
                    print(f"Hash written to: {args.output}", file=sys.stderr)
            except IOError as e:
                print(f"Error writing to output file: {e}", file=sys.stderr)
                return 1
            except PermissionError as e:
                print(f"Error: Permission denied for output file '{args.output}': {e}", file=sys.stderr)
                return 1
        else:
            if args.binary:
                sys.stdout.buffer.write(hasher.digest())
            else:
                print(output_line)

    except PermissionError as e:
        print(f"Error: Permission denied for file '{args.input}': {e}", file=sys.stderr)
        return 1
    except IOError as e:
        print(f"Error reading file '{args.input}': {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error during hashing: {e}", file=sys.stderr)
        return 1

    return 0


def encrypt_command(args):
    """Обработка команды шифрования/расшифрования."""
    if not HAS_ENCRYPTION_MODULES:
        print("Error: Encryption modules are not available", file=sys.stderr)
        return 1

    if not (args.encrypt ^ args.decrypt):
        print("Error: Must specify either --encrypt or --decrypt", file=sys.stderr)
        return 1

    if args.decrypt and not args.key:
        print("Error: --key is required for decryption", file=sys.stderr)
        return 1

    # Обработка ключа
    key_bytes = None
    if args.key:
        try:
            key_bytes = validate_key(args.key)
            if check_weak_key(key_bytes):
                print("Warning: The provided key appears to be weak. Consider using a randomly generated key.",
                      file=sys.stderr)
        except ValueError as e:
            print(f"Error: Invalid key format: {e}", file=sys.stderr)
            return 1

    # Проверка файлов
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found", file=sys.stderr)
        return 1

    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        print(f"Error: Output directory '{output_dir}' does not exist", file=sys.stderr)
        return 1

    # Обработка AAD для GCM
    aad_bytes = b""
    if args.mode == 'gcm' and hasattr(args, 'aad') and args.aad:
        try:
            aad_bytes = bytes.fromhex(args.aad)
        except ValueError:
            print("Error: AAD must be valid hexadecimal", file=sys.stderr)
            return 1

    try:
        # ШИФРОВАНИЕ
        if args.encrypt:
            # Генерация ключа, если не предоставлен
            if not key_bytes:
                key_bytes = generate_random_bytes(16)
                print(f"Generated key: @{key_bytes.hex()}", file=sys.stderr)

            # Предупреждение для IV в GCM
            if args.mode == 'gcm' and args.iv:
                if not args.quiet:
                    print("Warning: For GCM encryption, nonce is generated automatically. Provided IV will be ignored.",
                          file=sys.stderr)

            # Чтение входных данных
            if HAS_FILE_IO:
                plaintext = read_file(args.input)
            else:
                with open(args.input, 'rb') as f:
                    plaintext = f.read()

            # ОБРАБОТКА GCM
            if args.mode == 'gcm':
                if not HAS_GCM:
                    print("Error: GCM mode is not available. Make sure gcm.py is in modes directory.", file=sys.stderr)
                    return 1

                cipher = GCM(key_bytes)
                ciphertext_with_tag = cipher.encrypt(plaintext, aad_bytes)

                # Запись в формате GCM: nonce (12) || ciphertext || tag (16)
                if HAS_FILE_IO:
                    write_gcm_file(args.output, cipher.nonce,
                                   ciphertext_with_tag[:-16], ciphertext_with_tag[-16:])
                else:
                    with open(args.output, 'wb') as f:
                        f.write(cipher.nonce)
                        f.write(ciphertext_with_tag)

                if not args.quiet:
                    print(f"Success: Encrypted {args.input} -> {args.output}", file=sys.stderr)
                    print(f"Nonce (hex): {cipher.nonce.hex()}", file=sys.stderr)
                    print(f"Tag (hex): {ciphertext_with_tag[-16:].hex()}", file=sys.stderr)
                    if aad_bytes:
                        print(f"AAD (hex): {aad_bytes.hex()}", file=sys.stderr)

                return 0

            # ОБРАБОТКА ДРУГИХ РЕЖИМОВ (CBC, CTR, и т.д.)
            cipher = get_cipher_instance(args.mode, key_bytes)
            ciphertext = cipher.encrypt(plaintext)

            # Запись результата
            if args.mode != 'ecb':
                # Для режимов с IV
                if HAS_FILE_IO:
                    write_file_with_iv(args.output, getattr(cipher, 'iv', b''), ciphertext)
                else:
                    with open(args.output, 'wb') as f:
                        if hasattr(cipher, 'iv'):
                            f.write(cipher.iv)
                        f.write(ciphertext)
            else:
                # Для ECB
                if HAS_FILE_IO:
                    write_file(args.output, ciphertext)
                else:
                    with open(args.output, 'wb') as f:
                        f.write(ciphertext)

            if not args.quiet:
                print(f"Success: Encrypted {args.input} -> {args.output}", file=sys.stderr)
                if args.mode != 'ecb' and hasattr(cipher, 'iv'):
                    print(f"IV (hex): {cipher.iv.hex()}", file=sys.stderr)

            return 0

        # РАСШИФРОВАНИЕ
        else:
            if not key_bytes:
                print("Error: Key is required for decryption", file=sys.stderr)
                return 1

            # ОБРАБОТКА GCM
            if args.mode == 'gcm':
                if not HAS_GCM:
                    print("Error: GCM mode is not available", file=sys.stderr)
                    return 1

                # Чтение файла в формате GCM
                if HAS_FILE_IO:
                    try:
                        nonce, ciphertext, tag = read_gcm_file(args.input)
                    except ValueError as e:
                        print(f"Error reading GCM file: {e}", file=sys.stderr)
                        return 1
                else:
                    with open(args.input, 'rb') as f:
                        data = f.read()

                    if len(data) < 28:
                        print("Error: Input file is too small for GCM format (minimum 28 bytes)", file=sys.stderr)
                        return 1

                    nonce = data[:12]
                    ciphertext_with_tag = data[12:]

                    if len(ciphertext_with_tag) < 16:
                        print("Error: Data too short to contain tag (minimum 16 bytes)", file=sys.stderr)
                        return 1

                    ciphertext = ciphertext_with_tag[:-16]
                    tag = ciphertext_with_tag[-16:]

                # Создаём GCM с указанным nonce
                cipher = GCM(key_bytes, nonce)

                try:
                    # Пытаемся расшифровать
                    plaintext = cipher.decrypt(ciphertext + tag, aad_bytes)
                except AuthenticationError as e:
                    print(f"[ERROR] Authentication failed: {e}", file=sys.stderr)
                    print("Possible causes: incorrect AAD, tampered ciphertext, or wrong key", file=sys.stderr)

                    # УДАЛЯЕМ ВЫХОДНОЙ ФАЙЛ, ЕСЛИ ОН БЫЛ СОЗДАН
                    if args.output and os.path.exists(args.output):
                        try:
                            os.remove(args.output)
                        except:
                            pass

                    return 1

                # Безопасная запись результата
                try:
                    if HAS_FILE_IO:
                        safe_write_file(args.output, plaintext)
                    else:
                        # Записываем во временный файл
                        temp_file = args.output + ".tmp"
                        with open(temp_file, 'wb') as f:
                            f.write(plaintext)
                        # Атомарная замена
                        if os.path.exists(args.output):
                            os.remove(args.output)
                        os.rename(temp_file, args.output)
                except Exception as e:
                    print(f"Error writing output file: {e}", file=sys.stderr)
                    return 1

                if not args.quiet:
                    print(f"Success: Decrypted {args.input} -> {args.output}", file=sys.stderr)

                return 0

            # ОБРАБОТКА ДРУГИХ РЕЖИМОВ
            iv_bytes = None
            if args.mode != 'ecb':
                if args.iv:
                    # IV предоставлен через аргумент
                    try:
                        iv_bytes = bytes.fromhex(args.iv)
                        if len(iv_bytes) != 16:
                            print("Error: IV must be 16 bytes (32 hex characters)", file=sys.stderr)
                            return 1
                    except ValueError:
                        print("Error: IV must be valid hexadecimal", file=sys.stderr)
                        return 1
                else:
                    # Чтение IV из файла
                    if HAS_FILE_IO:
                        try:
                            iv_bytes, ciphertext = read_file_with_iv(args.input)
                        except ValueError as e:
                            print(f"Error: {e}", file=sys.stderr)
                            return 1
                    else:
                        with open(args.input, 'rb') as f:
                            data = f.read()
                        if len(data) < 16:
                            print("Error: Input file is too small to contain IV", file=sys.stderr)
                            return 1
                        iv_bytes = data[:16]
                        ciphertext = data[16:]
            else:
                # Для ECB читаем весь файл как ciphertext
                if HAS_FILE_IO:
                    ciphertext = read_file(args.input)
                else:
                    with open(args.input, 'rb') as f:
                        ciphertext = f.read()

            # Создаём шифр и расшифровываем
            cipher = get_cipher_instance(args.mode, key_bytes, iv_bytes)

            try:
                plaintext = cipher.decrypt(ciphertext)
            except ValueError as e:
                print(f"Error: Decryption failed - {e}", file=sys.stderr)
                return 1

            # Запись результата
            if HAS_FILE_IO:
                write_file(args.output, plaintext)
            else:
                with open(args.output, 'wb') as f:
                    f.write(plaintext)

            if not args.quiet:
                print(f"Success: Decrypted {args.input} -> {args.output}", file=sys.stderr)

            return 0

    except FileNotFoundError as e:
        print(f"Error: File not found: {e}", file=sys.stderr)
        return 1
    except PermissionError as e:
        print(f"Error: Permission denied: {e}", file=sys.stderr)
        return 1
    except IOError as e:
        print(f"Error reading/writing file: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error during {'encryption' if args.encrypt else 'decryption'}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def parse_args():
    """Парсинг аргументов командной строки."""
    parser = argparse.ArgumentParser(
        description='CryptoCore - Cryptographic Tool with AES encryption, hash functions, HMAC, and AEAD',
        prog='cryptocore',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Hash examples
  cryptocore dgst --algorithm sha256 --input document.pdf
  cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
  echo "data" | cryptocore dgst --algorithm sha256 --input -

  # HMAC examples
  cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt
  cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify expected.txt

  # Encryption examples (traditional modes)
  cryptocore encrypt --mode cbc --encrypt --key @00112233445566778899aabbccddeeff --input plain.txt --output encrypted.bin
  cryptocore encrypt --mode cbc --decrypt --key @00112233445566778899aabbccddeeff --input encrypted.bin --output decrypted.txt

  # GCM examples (authenticated encryption)
  cryptocore encrypt --mode gcm --encrypt --key @00112233445566778899aabbccddeeff --input plain.txt --output encrypted.bin --aad aabbccddeeff
  cryptocore encrypt --mode gcm --decrypt --key @00112233445566778899aabbccddeeff --input encrypted.bin --output decrypted.txt --aad aabbccddeeff
        '''
    )

    subparsers = parser.add_subparsers(
        dest='command',
        help='Command to execute',
        required=True,
        metavar='COMMAND'
    )

    # Парсер для шифрования
    encrypt_parser = subparsers.add_parser(
        'encrypt',
        help='Encrypt or decrypt files using AES',
        description='Encrypt or decrypt files using AES-128 with various modes including GCM for authenticated encryption'
    )

    encrypt_parser.add_argument('--algorithm',
                                choices=['aes'],
                                default='aes',
                                help='Encryption algorithm (default: aes)')

    encrypt_parser.add_argument('--mode',
                                choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr', 'gcm'],
                                required=True,
                                help='Block cipher mode of operation (gcm for authenticated encryption)')

    encrypt_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    encrypt_group.add_argument('--encrypt',
                               action='store_true',
                               help='Encrypt mode')
    encrypt_group.add_argument('--decrypt',
                               action='store_true',
                               help='Decrypt mode')

    encrypt_parser.add_argument('--key',
                                help='Encryption key as @ + 32 hex chars (e.g., @00112233445566778899aabbccddeeff)')

    encrypt_parser.add_argument('--input',
                                required=True,
                                help='Input file path')

    encrypt_parser.add_argument('--output',
                                required=True,
                                help='Output file path')

    encrypt_parser.add_argument('--iv',
                                help='Initialization vector as 32 hex chars (for modes that require it). For GCM, this is the nonce (24 hex chars for 12 bytes).')

    encrypt_parser.add_argument('--aad',
                                help='Additional Authenticated Data as hex string (for GCM mode only)')

    encrypt_parser.add_argument('--quiet',
                                action='store_true',
                                help='Suppress informational messages')

    # Парсер для хеширования/HMAC
    dgst_parser = subparsers.add_parser(
        'dgst',
        help='Compute message digests (hash functions) and HMAC',
        description='Compute cryptographic hash values and HMAC for files'
    )

    dgst_parser.add_argument('--algorithm',
                             choices=['sha256', 'sha3-256'],
                             required=True,
                             help='Hash algorithm to use')

    dgst_parser.add_argument('--hmac',
                             action='store_true',
                             help='Enable HMAC mode (requires --key)')

    dgst_parser.add_argument('--key',
                             help='Key for HMAC (hexadecimal string, e.g., 00112233445566778899aabbccddeeff)')

    dgst_parser.add_argument('--verify',
                             help='Verify HMAC against file with expected value')

    dgst_parser.add_argument('--input',
                             required=True,
                             help='Input file path (use "-" for stdin)')

    dgst_parser.add_argument('--output',
                             help='Write hash/HMAC to file instead of stdout')

    dgst_parser.add_argument('--binary',
                             action='store_true',
                             help='Output binary hash/HMAC instead of hex')

    dgst_parser.add_argument('--quiet',
                             action='store_true',
                             help='Suppress informational messages')

    return parser.parse_args()


def main():
    """Основная функция."""
    try:
        args = parse_args()

        if args.command == 'dgst':
            return dgst_command(args)
        elif args.command == 'encrypt':
            return encrypt_command(args)
        else:
            print(f"Error: Unknown command '{args.command}'", file=sys.stderr)
            return 1

    except KeyboardInterrupt:
        if not getattr(args, 'quiet', False):
            print("\nOperation cancelled by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())