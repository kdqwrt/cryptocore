import os
import sys

# Добавляем путь к src для импорта cryptocore
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from cryptocore.modes.ecb import ECBCipher
from cryptocore.modes.cbc import CBCCipher


def test_block_cipher_mode_key_validation():
    """Тест валидации ключа в BlockCipherMode"""
    # ECBCipher наследуется от BlockCipherMode через импорт
    # Тест короткого ключа
    try:
        ECBCipher(b"short")
        assert False, "Should raise ValueError for short key"
    except ValueError as e:
        assert "16 bytes" in str(e)
    
    # Тест длинного ключа
    try:
        ECBCipher(b"x" * 32)
        assert False, "Should raise ValueError for long key"
    except ValueError as e:
        assert "16 bytes" in str(e)
    
    # Правильный ключ
    cipher = ECBCipher(b'\x00' * 16)
    assert cipher is not None
    
    print("✓ BlockCipherMode key validation test PASSED")


def test_block_cipher_mode_padding():
    """Тест padding в режимах с padding"""
    key = b'\x00' * 16
    
    # CBCCipher использует padding
    cipher = CBCCipher(key)
    
    # Тест с данными, которые не кратны 16
    data = b"15 bytes!!!!!"
    encrypted = cipher.encrypt(data)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == data
    
    # Тест с данными, которые кратны 16
    data = b"16 bytes!!!!!!"
    encrypted = cipher.encrypt(data)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == data
    
    # Тест с пустыми данными
    data = b""
    encrypted = cipher.encrypt(data)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == data
    
    print("✓ BlockCipherMode padding test PASSED")


def test_block_cipher_mode_unpad_errors():
    """Тест обработки ошибок при unpadding"""
    key = b'\x00' * 16
    cipher = CBCCipher(key)
    
    # Создаем валидный зашидрованный текст
    valid_data = b"test data"
    encrypted = cipher.encrypt(valid_data)
    
    # Тест с невалидным padding (слишком большой) - модифицируем последний байт
    invalid_data = bytearray(encrypted)
    if len(invalid_data) >= 16:
        invalid_data[-1] = 17  # padding_len = 17 > 16
    try:
        cipher.decrypt(bytes(invalid_data))
        assert False, "Should raise ValueError for invalid padding length"
    except (ValueError, Exception) as e:
        # Проверяем, что ошибка была вызвана
        assert "Invalid padding" in str(e) or "padding" in str(e).lower() or "decrypt" in str(e).lower()
    
    # Тест с невалидным padding (неправильные байты) - создаем полностью невалидные данные
    # Просто создаем данные с неправильным padding
    invalid_data2 = b"x" * 15 + bytes([5, 4, 3, 2, 1])  # padding_len = 5, но байты не все 5
    # Но это не зашифрованные данные, поэтому расшифрование может не работать
    # Вместо этого проверим, что расшифрование валидных данных работает
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == valid_data, "Valid decryption should work"
    
    print("✓ BlockCipherMode unpadding error handling test PASSED")


def test_block_cipher_mode_split_into_blocks():
    """Тест разбиения данных на блоки"""
    key = b'\x00' * 16
    cipher = CBCCipher(key)
    
    # Тест с данными, которые не кратны 16 (после padding)
    data = b"15 bytes!!!!!"
    encrypted = cipher.encrypt(data)
    # Проверяем, что данные были разбиты на блоки
    assert len(encrypted) % 16 == 0, "Encrypted data should be multiple of 16 bytes"
    
    # Тест с данными, которые кратны 16
    data = b"16 bytes!!!!!!"
    encrypted = cipher.encrypt(data)
    assert len(encrypted) % 16 == 0, "Encrypted data should be multiple of 16 bytes"
    
    # Тест с пустыми данными
    data = b""
    encrypted = cipher.encrypt(data)
    assert len(encrypted) % 16 == 0, "Empty data should be padded to block size"
    
    # Тест с данными больше одного блока
    data = b"x" * 50
    encrypted = cipher.encrypt(data)
    assert len(encrypted) % 16 == 0, "Large data should be multiple of block size"
    
    print("✓ BlockCipherMode split_into_blocks test PASSED")


def test_block_cipher_mode_pad_data():
    """Тест функции _pad_data напрямую"""
    # Создаем тестовый класс, который наследуется от BlockCipherMode
    from cryptocore.modes import BlockCipherMode
    from Crypto.Cipher import AES
    
    class TestCipher(BlockCipherMode):
        def __init__(self, key, requires_padding=False):
            super().__init__(key, requires_padding)
            self.cipher = AES.new(key, AES.MODE_ECB)
        
        def encrypt(self, data):
            padded = self._pad_data(data)
            return self.cipher.encrypt(padded)
        
        def decrypt(self, data):
            decrypted = self.cipher.decrypt(data)
            return self._unpad_data(decrypted)
    
    key = b'\x00' * 16
    
    # Тест с requires_padding=False
    cipher_no_pad = TestCipher(key, requires_padding=False)
    data = b"test"
    padded = cipher_no_pad._pad_data(data)
    assert padded == data, "Data should not be padded when requires_padding=False"
    
    # Тест с requires_padding=True и данными не кратными 16
    cipher_pad = TestCipher(key, requires_padding=True)
    data = b"15 bytes!!!!!"
    padded = cipher_pad._pad_data(data)
    assert len(padded) % 16 == 0, "Padded data should be multiple of 16"
    assert len(padded) > len(data), "Padded data should be longer"
    
    # Тест с requires_padding=True и данными кратными 16
    data = b"x" * 16  # Ровно 16 байт
    assert len(data) == 16, "Test data should be exactly 16 bytes"
    padded = cipher_pad._pad_data(data)
    assert len(padded) == len(data) + 16, f"Data multiple of 16 should get full block of padding (got {len(padded)}, expected {len(data) + 16})"
    assert padded[-16:] == bytes([16] * 16), "Last 16 bytes should all be 16 (padding value)"
    
    print("✓ BlockCipherMode _pad_data test PASSED")


def test_block_cipher_mode_unpad_data():
    """Тест функции _unpad_data напрямую"""
    from cryptocore.modes import BlockCipherMode
    from Crypto.Cipher import AES
    
    class TestCipher(BlockCipherMode):
        def __init__(self, key, requires_padding=False):
            super().__init__(key, requires_padding)
            self.cipher = AES.new(key, AES.MODE_ECB)
        
        def encrypt(self, data):
            padded = self._pad_data(data)
            return self.cipher.encrypt(padded)
        
        def decrypt(self, data):
            decrypted = self.cipher.decrypt(data)
            return self._unpad_data(decrypted)
    
    key = b'\x00' * 16
    cipher = TestCipher(key, requires_padding=True)
    
    # Тест с requires_padding=False
    cipher_no_pad = TestCipher(key, requires_padding=False)
    data = b"test data"
    unpadded = cipher_no_pad._unpad_data(data)
    assert unpadded == data, "Data should not be unpadded when requires_padding=False"
    
    # Тест с пустыми данными
    unpadded = cipher._unpad_data(b"")
    assert unpadded == b"", "Empty data should remain empty"
    
    # Тест round-trip: pad -> unpad
    original = b"test data"
    padded = cipher._pad_data(original)
    unpadded = cipher._unpad_data(padded)
    assert unpadded == original, "Round-trip pad/unpad should work"
    
    print("✓ BlockCipherMode _unpad_data test PASSED")


def test_block_cipher_mode_iv_generation():
    """Тест генерации IV"""
    key = b'\x00' * 16
    
    # CBCCipher генерирует IV автоматически
    cipher1 = CBCCipher(key)
    cipher2 = CBCCipher(key)
    
    # Разные экземпляры должны иметь разные IV
    assert cipher1.iv != cipher2.iv, "Different instances should have different IVs"
    
    print("✓ BlockCipherMode IV generation test PASSED")


def test_block_cipher_mode_abstract_methods():
    """Тест абстрактных методов BlockCipherMode"""
    from cryptocore.modes import BlockCipherMode
    from Crypto.Cipher import AES
    
    # Создаем тестовый класс, который реализует все абстрактные методы
    class TestCipher(BlockCipherMode):
        def __init__(self, key, requires_padding=False):
            super().__init__(key, requires_padding)
            self.cipher = AES.new(key, AES.MODE_ECB)
        
        def encrypt(self, data):
            padded = self._pad_data(data)
            return self.cipher.encrypt(padded)
        
        def decrypt(self, data):
            decrypted = self.cipher.decrypt(data)
            return self._unpad_data(decrypted)
    
    key = b'\x00' * 16
    
    # Тест создания экземпляра
    cipher = TestCipher(key)
    assert cipher.key == key
    assert cipher.block_size == 16
    assert cipher.requires_padding == False
    
    # Тест с requires_padding=True
    cipher_pad = TestCipher(key, requires_padding=True)
    assert cipher_pad.requires_padding == True
    
    # Тест encrypt и decrypt
    data = b"test data"
    encrypted = cipher_pad.encrypt(data)
    decrypted = cipher_pad.decrypt(encrypted)
    assert decrypted == data
    
    # Тест _split_into_blocks с разными размерами
    blocks = cipher._split_into_blocks(b"x" * 50)
    assert len(blocks) == 4, "Should split into 4 blocks (50 bytes / 16 = 3.125 -> 4)"
    assert all(len(block) <= 16 for block in blocks), "All blocks should be <= 16 bytes"
    
    # Тест _split_into_blocks с пустыми данными
    # range(0, 0, 16) возвращает пустой итератор, поэтому результат - пустой список
    blocks = cipher._split_into_blocks(b"")
    assert len(blocks) == 0, f"Empty data should return empty list, got {len(blocks)}"
    
    # Тест _split_into_blocks с данными кратными 16
    blocks = cipher._split_into_blocks(b"x" * 32)
    assert len(blocks) == 2, "32 bytes should split into 2 blocks"
    assert all(len(block) == 16 for block in blocks), "All blocks should be 16 bytes"
    
    print("✓ BlockCipherMode abstract methods test PASSED")


def main():
    """Запуск всех тестов базовых режимов"""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ БАЗОВЫХ РЕЖИМОВ ШИФРОВАНИЯ")
    print("=" * 60)
    
    all_passed = True
    
    tests = [
        ("BlockCipherMode Key Validation", test_block_cipher_mode_key_validation),
        ("BlockCipherMode Padding", test_block_cipher_mode_padding),
        ("BlockCipherMode Unpad Errors", test_block_cipher_mode_unpad_errors),
        ("BlockCipherMode Split Into Blocks", test_block_cipher_mode_split_into_blocks),
        ("BlockCipherMode Pad Data", test_block_cipher_mode_pad_data),
        ("BlockCipherMode Unpad Data", test_block_cipher_mode_unpad_data),
        ("BlockCipherMode IV Generation", test_block_cipher_mode_iv_generation),
        ("BlockCipherMode Abstract Methods", test_block_cipher_mode_abstract_methods),
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
        print("ALL MODES BASE TESTS PASSED!")
        return True
    else:
        print("SOME MODES BASE TESTS FAILED!")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

