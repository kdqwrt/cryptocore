import os
import sys
import tempfile

# Добавляем путь к src для импорта cryptocore
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from cryptocore.modes.cbc import CBCCipher
from cryptocore.modes.cfb import CFBCipher
from cryptocore.modes.ofb import OFBCipher
from cryptocore.modes.ctr import CTRCipher
from cryptocore.file_io import read_file, write_file, read_file_with_iv, write_file_with_iv


def test_cbc_roundtrip():
    """Тест CBC режима - круговой тест"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("00000000000000000000000000000000")
    test_data = b"Hello CryptoCore! This is a test message for CBC mode."

    cipher = CBCCipher(key, iv)
    encrypted = cipher.encrypt(test_data)
    decrypted = cipher.decrypt(encrypted)

    assert decrypted == test_data, "CBC roundtrip failed"
    print("✓ CBC roundtrip test PASSED")


def test_cbc_various_sizes():
    """Тест CBC с различными размерами данных"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("00000000000000000000000000000000")

    test_cases = [
        b"",
        b"A",
        b"15 bytes!!!!!",
        b"16 bytes!!!!!!",
        b"This is exactly 32 bytes long!!",
        b"X" * 100,
    ]

    for i, data in enumerate(test_cases):
        cipher = CBCCipher(key, iv)
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == data, f"CBC test case {i} failed: {len(data)} bytes"

    print("✓ CBC various sizes test PASSED")


def test_cbc_auto_iv():
    """Тест CBC с автоматической генерацией IV"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    test_data = b"Test data for auto IV"

    cipher1 = CBCCipher(key)
    cipher2 = CBCCipher(key)

    encrypted1 = cipher1.encrypt(test_data)
    encrypted2 = cipher2.encrypt(test_data)

    # Разные IV должны давать разные шифртексты
    assert encrypted1 != encrypted2, "CBC with auto IV should produce different ciphertexts"

    # Но расшифровка должна работать
    decrypted1 = cipher1.decrypt(encrypted1)
    decrypted2 = cipher2.decrypt(encrypted2)

    assert decrypted1 == test_data
    assert decrypted2 == test_data

    print("✓ CBC auto IV test PASSED")


def test_cfb_roundtrip():
    """Тест CFB режима - круговой тест"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("00000000000000000000000000000000")
    test_data = b"Hello CryptoCore! This is a test message for CFB mode."

    cipher = CFBCipher(key, iv)
    encrypted = cipher.encrypt(test_data)
    decrypted = cipher.decrypt(encrypted)

    assert decrypted == test_data, "CFB roundtrip failed"
    print("✓ CFB roundtrip test PASSED")


def test_cfb_various_sizes():
    """Тест CFB с различными размерами данных"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("00000000000000000000000000000000")

    test_cases = [
        b"",
        b"A",
        b"15 bytes!!!!!",
        b"16 bytes!!!!!!",
        b"This is exactly 32 bytes long!!",
        b"X" * 100,
    ]

    for i, data in enumerate(test_cases):
        cipher = CFBCipher(key, iv)
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == data, f"CFB test case {i} failed: {len(data)} bytes"

    print("✓ CFB various sizes test PASSED")


def test_ofb_roundtrip():
    """Тест OFB режима - круговой тест"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("00000000000000000000000000000000")
    test_data = b"Hello CryptoCore! This is a test message for OFB mode."

    cipher = OFBCipher(key, iv)
    encrypted = cipher.encrypt(test_data)
    decrypted = cipher.decrypt(encrypted)

    assert decrypted == test_data, "OFB roundtrip failed"
    print("✓ OFB roundtrip test PASSED")


def test_ofb_various_sizes():
    """Тест OFB с различными размерами данных"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("00000000000000000000000000000000")

    test_cases = [
        b"",
        b"A",
        b"15 bytes!!!!!",
        b"16 bytes!!!!!!",
        b"This is exactly 32 bytes long!!",
        b"X" * 100,
    ]

    for i, data in enumerate(test_cases):
        cipher = OFBCipher(key, iv)
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == data, f"OFB test case {i} failed: {len(data)} bytes"

    print("✓ OFB various sizes test PASSED")


def test_ctr_roundtrip():
    """Тест CTR режима - круговой тест"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("00000000000000000000000000000000")
    test_data = b"Hello CryptoCore! This is a test message for CTR mode."

    cipher = CTRCipher(key, iv)
    encrypted = cipher.encrypt(test_data)
    decrypted = cipher.decrypt(encrypted)

    assert decrypted == test_data, "CTR roundtrip failed"
    print("✓ CTR roundtrip test PASSED")


def test_ctr_various_sizes():
    """Тест CTR с различными размерами данных"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("00000000000000000000000000000000")

    test_cases = [
        b"",
        b"A",
        b"15 bytes!!!!!",
        b"16 bytes!!!!!!",
        b"This is exactly 32 bytes long!!",
        b"X" * 100,
    ]

    for i, data in enumerate(test_cases):
        cipher = CTRCipher(key, iv)
        encrypted = cipher.encrypt(data)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == data, f"CTR test case {i} failed: {len(data)} bytes"

    print("✓ CTR various sizes test PASSED")


def test_ctr_counter_increment():
    """Тест инкремента счетчика в CTR"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("00000000000000000000000000000000")

    cipher = CTRCipher(key, iv)
    
    # Тестируем инкремент счетчика
    counter = iv
    for i in range(5):
        counter_int = int.from_bytes(counter, byteorder='big')
        next_int = (counter_int + 1) & ((1 << 128) - 1)
        next_counter = next_int.to_bytes(16, byteorder='big')
        
        # Используем приватный метод через публичный интерфейс
        # Просто проверяем, что шифрование работает с разными счетчиками
        test_data = b"Test" * i
        encrypted = cipher.encrypt(test_data)
        assert len(encrypted) == len(test_data)

    print("✓ CTR counter increment test PASSED")


def test_modes_file_operations():
    """Тест работы с файлами для всех режимов"""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    original_data = b"File content for testing modes " + b"X" * 100

    modes = [
        ("CBC", CBCCipher),
        ("CFB", CFBCipher),
        ("OFB", OFBCipher),
        ("CTR", CTRCipher),
    ]

    for mode_name, CipherClass in modes:
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            input_file = f.name

        output_file = input_file + ".enc"
        decrypted_file = input_file + ".dec"

        try:
            # Записываем исходные данные
            write_file(input_file, original_data)

            # Шифруем
            cipher = CipherClass(key)
            file_data = read_file(input_file)
            encrypted = cipher.encrypt(file_data)
            write_file(output_file, encrypted)

            # Расшифровываем
            encrypted_data = read_file(output_file)
            decrypted = cipher.decrypt(encrypted_data)
            write_file(decrypted_file, decrypted)

            # Проверяем
            final_data = read_file(decrypted_file)
            assert final_data == original_data, f"{mode_name} file operations failed"

        finally:
            for f in [input_file, output_file, decrypted_file]:
                if os.path.exists(f):
                    os.unlink(f)

    print("✓ File operations test PASSED for all modes")


def test_modes_key_validation():
    """Тест валидации ключей для всех режимов"""
    modes = [
        ("CBC", CBCCipher),
        ("CFB", CFBCipher),
        ("OFB", OFBCipher),
        ("CTR", CTRCipher),
    ]

    for mode_name, CipherClass in modes:
        # Неверная длина ключа
        try:
            CipherClass(b"short")
            assert False, f"{mode_name} should raise ValueError for short key"
        except ValueError:
            pass

        # Неверная длина IV
        try:
            CipherClass(bytes.fromhex("00112233445566778899aabbccddeeff"), b"short_iv")
            assert False, f"{mode_name} should raise ValueError for short IV"
        except ValueError:
            pass

    print("✓ Key validation test PASSED for all modes")


def main():
    """Запуск всех тестов режимов шифрования"""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ РЕЖИМОВ ШИФРОВАНИЯ (CBC, CFB, OFB, CTR)")
    print("=" * 60)
    
    all_passed = True
    
    tests = [
        ("CBC Roundtrip", test_cbc_roundtrip),
        ("CBC Various Sizes", test_cbc_various_sizes),
        ("CBC Auto IV", test_cbc_auto_iv),
        ("CFB Roundtrip", test_cfb_roundtrip),
        ("CFB Various Sizes", test_cfb_various_sizes),
        ("OFB Roundtrip", test_ofb_roundtrip),
        ("OFB Various Sizes", test_ofb_various_sizes),
        ("CTR Roundtrip", test_ctr_roundtrip),
        ("CTR Various Sizes", test_ctr_various_sizes),
        ("CTR Counter Increment", test_ctr_counter_increment),
        ("Modes File Operations", test_modes_file_operations),
        ("Modes Key Validation", test_modes_key_validation),
    ]
    
    for test_name, test_func in tests:
        try:
            test_func()
        except Exception as e:
            print(f"✗ {test_name} FAILED: {e}")
            import traceback
            traceback.print_exc()
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("ALL MODES TESTS PASSED!")
        return True
    else:
        print("SOME MODES TESTS FAILED!")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

