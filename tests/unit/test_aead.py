import os
import sys
import tempfile

# Добавляем путь к src для импорта cryptocore
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from cryptocore.aead import EncryptThenMAC, AuthenticationError, derive_keys_from_master


def test_encrypt_then_mac_basic():
    """Базовый тест Encrypt-then-MAC"""
    key = b'\x00' * 32  # 32 байта для enc_key (16) + mac_key (16)
    plaintext = b"Test message for ETM"
    aad = b"Additional authenticated data"
    
    etm = EncryptThenMAC(key)
    ciphertext, tag, iv = etm.encrypt(plaintext, aad)
    
    # Проверяем, что получили все компоненты
    assert ciphertext is not None, "Ciphertext should not be None"
    assert tag is not None, "Tag should not be None"
    assert len(tag) == 32, "Tag should be 32 bytes for SHA-256"
    
    # Расшифровываем
    decrypted = etm.decrypt(ciphertext, tag, aad, iv)
    assert decrypted == plaintext, "Decryption failed"
    
    print("✓ Encrypt-then-MAC basic test PASSED")


def test_encrypt_then_mac_different_modes():
    """Тест Encrypt-then-MAC с разными режимами шифрования"""
    key = b'\x00' * 32
    plaintext = b"Test message"
    
    modes = ['ctr', 'cbc', 'cfb', 'ofb', 'ecb']
    
    for mode in modes:
        etm = EncryptThenMAC(key, encryption_mode=mode)
        ciphertext, tag, iv = etm.encrypt(plaintext)
        
        decrypted = etm.decrypt(ciphertext, tag, b"", iv)
        assert decrypted == plaintext, f"ETM with {mode} mode failed"
    
    print("✓ Encrypt-then-MAC different modes test PASSED")


def test_encrypt_then_mac_different_hash_algorithms():
    """Тест Encrypt-then-MAC с разными алгоритмами хеширования"""
    key = b'\x00' * 32
    plaintext = b"Test message"
    
    algorithms = ['sha256', 'sha3-256']
    
    for alg in algorithms:
        etm = EncryptThenMAC(key, hash_algorithm=alg)
        ciphertext, tag, iv = etm.encrypt(plaintext)
        
        decrypted = etm.decrypt(ciphertext, tag, b"", iv)
        assert decrypted == plaintext, f"ETM with {alg} algorithm failed"
    
    print("✓ Encrypt-then-MAC different hash algorithms test PASSED")


def test_encrypt_then_mac_aad():
    """Тест Encrypt-then-MAC с AAD"""
    key = b'\x00' * 32
    plaintext = b"Test message"
    aad1 = b"AAD 1"
    aad2 = b"AAD 2"
    
    etm = EncryptThenMAC(key)
    ciphertext, tag, iv = etm.encrypt(plaintext, aad1)
    
    # Правильный AAD должен пройти
    decrypted = etm.decrypt(ciphertext, tag, aad1, iv)
    assert decrypted == plaintext, "Decryption with correct AAD failed"
    
    # Неправильный AAD должен вызвать ошибку
    try:
        etm.decrypt(ciphertext, tag, aad2, iv)
        assert False, "Should raise AuthenticationError for wrong AAD"
    except AuthenticationError:
        pass
    
    print("✓ Encrypt-then-MAC AAD test PASSED")


def test_encrypt_then_mac_tamper_detection():
    """Тест обнаружения подмены в Encrypt-then-MAC"""
    key = b'\x00' * 32
    plaintext = b"Test message"
    
    etm = EncryptThenMAC(key)
    ciphertext, tag, iv = etm.encrypt(plaintext)
    
    # Подмена шифртекста
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 1
    
    try:
        etm.decrypt(bytes(tampered_ciphertext), tag, b"", iv)
        assert False, "Should raise AuthenticationError for tampered ciphertext"
    except AuthenticationError:
        pass
    
    # Подмена тега
    tampered_tag = bytearray(tag)
    tampered_tag[0] ^= 1
    
    try:
        etm.decrypt(ciphertext, bytes(tampered_tag), b"", iv)
        assert False, "Should raise AuthenticationError for tampered tag"
    except AuthenticationError:
        pass
    
    print("✓ Encrypt-then-MAC tamper detection test PASSED")


def test_encrypt_then_mac_key_validation():
    """Тест валидации ключа в Encrypt-then-MAC"""
    # Ключ слишком короткий
    try:
        EncryptThenMAC(b"short")
        assert False, "Should raise ValueError for short key"
    except ValueError as e:
        assert "32 байта" in str(e) or "минимум" in str(e).lower()
    
    # Ключ правильной длины
    key = b'\x00' * 32
    etm = EncryptThenMAC(key)
    assert etm is not None
    
    print("✓ Encrypt-then-MAC key validation test PASSED")


def test_encrypt_then_mac_unsupported_mode():
    """Тест неподдерживаемого режима шифрования"""
    key = b'\x00' * 32
    
    try:
        EncryptThenMAC(key, encryption_mode='unsupported')
        assert False, "Should raise ValueError for unsupported mode"
    except ValueError as e:
        assert "режим" in str(e).lower() or "mode" in str(e).lower()
    
    print("✓ Encrypt-then-MAC unsupported mode test PASSED")


def test_derive_keys_from_master():
    """Тест функции derive_keys_from_master"""
    # Ключ длиной 32+ байта
    master_key_32 = b'\x00' * 32
    enc_key, mac_key = derive_keys_from_master(master_key_32)
    
    assert len(enc_key) == 16, "Encryption key should be 16 bytes"
    assert len(mac_key) == 16, "MAC key should be 16 bytes"
    assert enc_key == master_key_32[:16], "Encryption key should be first 16 bytes"
    assert mac_key == master_key_32[16:32], "MAC key should be next 16 bytes"
    
    # Ключ длиной 16-31 байт
    master_key_16 = b'\x00' * 16
    enc_key, mac_key = derive_keys_from_master(master_key_16)
    
    assert len(enc_key) == 16, "Encryption key should be 16 bytes"
    assert len(mac_key) == 16, "MAC key should be 16 bytes"
    assert enc_key == master_key_16[:16], "Encryption key should be first 16 bytes"
    
    # Ключ слишком короткий
    try:
        derive_keys_from_master(b"short")
        assert False, "Should raise ValueError for short key"
    except ValueError as e:
        assert "16 байт" in str(e) or "минимум" in str(e).lower()
    
    print("✓ Derive keys from master test PASSED")


def test_encrypt_then_mac_empty_plaintext():
    """Тест Encrypt-then-MAC с пустым plaintext"""
    key = b'\x00' * 32
    plaintext = b""
    
    etm = EncryptThenMAC(key)
    ciphertext, tag, iv = etm.encrypt(plaintext)
    
    decrypted = etm.decrypt(ciphertext, tag, b"", iv)
    assert decrypted == plaintext, "Empty plaintext test failed"
    
    print("✓ Encrypt-then-MAC empty plaintext test PASSED")


def test_encrypt_then_mac_large_data():
    """Тест Encrypt-then-MAC с большими данными"""
    key = b'\x00' * 32
    plaintext = b"X" * 10000
    
    etm = EncryptThenMAC(key)
    ciphertext, tag, iv = etm.encrypt(plaintext)
    
    decrypted = etm.decrypt(ciphertext, tag, b"", iv)
    assert decrypted == plaintext, "Large data test failed"
    
    print("✓ Encrypt-then-MAC large data test PASSED")


def main():
    """Запуск всех тестов AEAD"""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ AEAD МОДУЛЯ")
    print("=" * 60)
    
    all_passed = True
    
    tests = [
        ("Encrypt-then-MAC Basic", test_encrypt_then_mac_basic),
        ("Encrypt-then-MAC Different Modes", test_encrypt_then_mac_different_modes),
        ("Encrypt-then-MAC Different Hash Algorithms", test_encrypt_then_mac_different_hash_algorithms),
        ("Encrypt-then-MAC AAD", test_encrypt_then_mac_aad),
        ("Encrypt-then-MAC Tamper Detection", test_encrypt_then_mac_tamper_detection),
        ("Encrypt-then-MAC Key Validation", test_encrypt_then_mac_key_validation),
        ("Encrypt-then-MAC Unsupported Mode", test_encrypt_then_mac_unsupported_mode),
        ("Derive Keys From Master", test_derive_keys_from_master),
        ("Encrypt-then-MAC Empty Plaintext", test_encrypt_then_mac_empty_plaintext),
        ("Encrypt-then-MAC Large Data", test_encrypt_then_mac_large_data),
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
        print("ALL AEAD TESTS PASSED!")
        return True
    else:
        print("SOME AEAD TESTS FAILED!")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

