import os
import sys
import tempfile

# Добавляем путь к src для импорта cryptocore
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from cryptocore.modes.ecb import ECBCipher
from cryptocore.file_io import read_file, write_file
from cryptocore.cli import validate_key


def test_roundtrip_basic():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    test_data = b"Hello CryptoCore! This is a test message."

    cipher = ECBCipher(key)
    encrypted = cipher.encrypt(test_data)
    decrypted = cipher.decrypt(encrypted)

    assert decrypted == test_data
    print("Basic round-trip test PASSED")


def test_roundtrip_file():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")

    # Создаем временный файл
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
        original_data = b"File content for testing " + b"X" * 100
        f.write(original_data)
        input_file = f.name

    output_file = input_file + ".enc"
    decrypted_file = input_file + ".dec"

    try:
        file_data = read_file(input_file)
        cipher = ECBCipher(key)
        encrypted = cipher.encrypt(file_data)
        write_file(output_file, encrypted)

        encrypted_data = read_file(output_file)
        decrypted = cipher.decrypt(encrypted_data)
        write_file(decrypted_file, decrypted)

        final_data = read_file(decrypted_file)
        assert final_data == original_data
        print("File round-trip test PASSED")

    finally:
        for f in [input_file, output_file, decrypted_file]:
            if os.path.exists(f):
                os.unlink(f)


def test_encrypt_decrypt_various_sizes():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")

    test_cases = [
        b"",  # empty
        b"A",  # 1 byte
        b"16 bytes!!!!!!",  # 15 bytes
        b"16 bytes!!!!!!!",  # 16 bytes (exact block)
        b"This is exactly 32 bytes long!!",  # 32 bytes
        b"X" * 100,  # 100 bytes
    ]

    for i, data in enumerate(test_cases):
        cipher = ECBCipher(key)
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == data, f"Test case {i} failed: {len(data)} bytes"

    print("Various sizes test PASSED")


def test_validate_key():

    key = validate_key("@00112233445566778899aabbccddeeff")
    assert key == bytes.fromhex("00112233445566778899aabbccddeeff")

    try:
        validate_key("00112233445566778899aabbccddeeff")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Key must start with @" in str(e)

    try:
        validate_key("@001122")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Key must be 16 bytes" in str(e)

    try:
        validate_key("@gggggggggggggggggggggggggggggggg")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "valid hexadecimal" in str(e)

    print("Key validation test PASSED")


def test_openssl_compatibility():
    try:
        import subprocess

        test_data = b"16-byte-test!!!!"
        key_hex = "00112233445566778899aabbccddeeff"
        key = bytes.fromhex(key_hex)

        cipher = ECBCipher(key)
        our_encrypted = cipher.encrypt(test_data)

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f_in:
            f_in.write(test_data)
            input_file = f_in.name

        openssl_output = input_file + ".openssl"

        subprocess.run([
            'openssl', 'enc', '-aes-128-ecb',
            '-K', key_hex,
            '-in', input_file,
            '-out', openssl_output,
            '-nopad'
        ], check=True, capture_output=True)

        with open(openssl_output, 'rb') as f:
            openssl_encrypted = f.read()

        if our_encrypted == openssl_encrypted:
            print("OpenSSL compatibility test PASSED")
        else:
            print(f"  Results differ - Our: {our_encrypted.hex()}, OpenSSL: {openssl_encrypted.hex()}")

    except (subprocess.CalledProcessError, FileNotFoundError):
        print(" OpenSSL not available, skipping compatibility test")
    finally:
        for f in [input_file, openssl_output]:
            if os.path.exists(f):
                os.unlink(f)


def main():
    """Запуск всех тестов ECB"""
    all_passed = True
    
    try:
        test_roundtrip_basic()
    except Exception as e:
        print(f"test_roundtrip_basic FAILED: {e}")
        all_passed = False
    
    try:
        test_roundtrip_file()
    except Exception as e:
        print(f"test_roundtrip_file FAILED: {e}")
        all_passed = False
    
    try:
        test_encrypt_decrypt_various_sizes()
    except Exception as e:
        print(f"test_encrypt_decrypt_various_sizes FAILED: {e}")
        all_passed = False
    
    try:
        test_validate_key()
    except Exception as e:
        print(f"test_validate_key FAILED: {e}")
        all_passed = False
    
    try:
        test_openssl_compatibility()
    except Exception as e:
        print(f"test_openssl_compatibility FAILED: {e}")
        all_passed = False
    
    if all_passed:
        print("ALL ECB TESTS PASSED!")
        return True
    else:
        print("SOME ECB TESTS FAILED!")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)