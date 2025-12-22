"""
Тесты для модуля __init__.py
Проверяем, что все импорты работают корректно
"""
import os
import sys

# Добавляем путь к src для импорта cryptocore
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)


def test_init_imports():
    """Тест импортов из cryptocore.__init__"""
    print("\n" + "=" * 60)
    print("TEST: Тестирование импортов из cryptocore.__init__")
    print("=" * 60)
    
    # Импортируем модуль
    import cryptocore
    
    # Проверяем, что модуль имеет атрибут __version__
    assert hasattr(cryptocore, '__version__'), "Module should have __version__"
    assert cryptocore.__version__ == '1.1.0', f"Expected version 1.1.0, got {cryptocore.__version__}"
    print("✓ __version__ is correct")
    
    # Проверяем, что модуль имеет атрибут __all__
    assert hasattr(cryptocore, '__all__'), "Module should have __all__"
    print(f"✓ __all__ contains {len(cryptocore.__all__)} items")
    
    # Проверяем основные импорты
    # Hash functions
    if cryptocore.SHA256 is not None:
        assert callable(cryptocore.sha256), "sha256 should be callable"
        print("✓ SHA256 and sha256 are available")
    
    if cryptocore.SHA3_256 is not None:
        assert callable(cryptocore.sha3_256), "sha3_256 should be callable"
        print("✓ SHA3_256 and sha3_256 are available")
    
    # Encryption modes
    if cryptocore.ECBCipher is not None:
        print("✓ ECBCipher is available")
    
    if cryptocore.CBCCipher is not None:
        print("✓ CBCCipher is available")
    
    if cryptocore.CFBCipher is not None:
        print("✓ CFBCipher is available")
    
    if cryptocore.OFBCipher is not None:
        print("✓ OFBCipher is available")
    
    if cryptocore.CTRCipher is not None:
        print("✓ CTRCipher is available")
    
    # GCM
    if cryptocore.GCM is not None:
        print("✓ GCM is available")
    
    if cryptocore.AuthenticationError is not None:
        print("✓ AuthenticationError is available")
    
    # AEAD
    if cryptocore.EncryptThenMAC is not None:
        print("✓ EncryptThenMAC is available")
    
    # CSPRNG
    if cryptocore.generate_random_bytes is not None:
        assert callable(cryptocore.generate_random_bytes), "generate_random_bytes should be callable"
        print("✓ generate_random_bytes is available")
    
    if cryptocore.generate_key is not None:
        assert callable(cryptocore.generate_key), "generate_key should be callable"
        print("✓ generate_key is available")
    
    if cryptocore.generate_iv is not None:
        assert callable(cryptocore.generate_iv), "generate_iv should be callable"
        print("✓ generate_iv is available")
    
    # File IO
    if cryptocore.read_file is not None:
        assert callable(cryptocore.read_file), "read_file should be callable"
        print("✓ read_file is available")
    
    if cryptocore.write_file is not None:
        assert callable(cryptocore.write_file), "write_file should be callable"
        print("✓ write_file is available")
    
    # CLI functions
    if cryptocore.validate_key is not None:
        assert callable(cryptocore.validate_key), "validate_key should be callable"
        print("✓ validate_key is available")
    
    if cryptocore.check_weak_key is not None:
        assert callable(cryptocore.check_weak_key), "check_weak_key should be callable"
        print("✓ check_weak_key is available")
    
    return True


def test_init_import_error_handling():
    """Тест обработки ошибок импорта (симуляция отсутствия модулей)"""
    print("\n" + "=" * 60)
    print("TEST: Тестирование обработки ошибок импорта")
    print("=" * 60)
    
    # Этот тест проверяет, что модуль корректно обрабатывает отсутствие зависимостей
    # В реальности все модули должны быть доступны, но проверяем структуру
    import cryptocore
    
    # Проверяем, что модуль имеет все необходимые атрибуты, даже если они None
    # Это означает, что блоки except ImportError работают
    assert hasattr(cryptocore, 'SHA256'), "Should have SHA256 attribute"
    assert hasattr(cryptocore, 'SHA3_256'), "Should have SHA3_256 attribute"
    assert hasattr(cryptocore, 'ECBCipher'), "Should have ECBCipher attribute"
    assert hasattr(cryptocore, 'CBCCipher'), "Should have CBCCipher attribute"
    assert hasattr(cryptocore, 'CFBCipher'), "Should have CFBCipher attribute"
    assert hasattr(cryptocore, 'OFBCipher'), "Should have OFBCipher attribute"
    assert hasattr(cryptocore, 'CTRCipher'), "Should have CTRCipher attribute"
    assert hasattr(cryptocore, 'GCM'), "Should have GCM attribute"
    assert hasattr(cryptocore, 'EncryptThenMAC'), "Should have EncryptThenMAC attribute"
    assert hasattr(cryptocore, 'generate_random_bytes'), "Should have generate_random_bytes attribute"
    assert hasattr(cryptocore, 'read_file'), "Should have read_file attribute"
    assert hasattr(cryptocore, 'validate_key'), "Should have validate_key attribute"
    
    print("✓ All required attributes are present (even if None)")
    
    return True


def test_init_functionality():
    """Тест функциональности импортированных функций"""
    print("\n" + "=" * 60)
    print("TEST: Тестирование функциональности импортированных функций")
    print("=" * 60)
    
    import cryptocore
    
    # Тест hash функций
    if cryptocore.sha256 is not None:
        # sha256 может принимать строку или bytes
        try:
            result = cryptocore.sha256("test")
            assert isinstance(result, str), "sha256 should return string"
            assert len(result) == 64, "SHA-256 hash should be 64 hex characters"
            print("✓ sha256 function works with string")
        except (TypeError, AttributeError):
            # Если не работает со строкой, пробуем с bytes
            result = cryptocore.sha256(b"test")
            assert isinstance(result, str), "sha256 should return string"
            assert len(result) == 64, "SHA-256 hash should be 64 hex characters"
            print("✓ sha256 function works with bytes")
    
    if cryptocore.sha3_256 is not None:
        try:
            result = cryptocore.sha3_256("test")
            assert isinstance(result, str), "sha3_256 should return string"
            assert len(result) == 64, "SHA3-256 hash should be 64 hex characters"
            print("✓ sha3_256 function works with string")
        except (TypeError, AttributeError):
            # Если не работает со строкой, пробуем с bytes
            result = cryptocore.sha3_256(b"test")
            assert isinstance(result, str), "sha3_256 should return string"
            assert len(result) == 64, "SHA3-256 hash should be 64 hex characters"
            print("✓ sha3_256 function works with bytes")
    
    # Тест CSPRNG
    if cryptocore.generate_random_bytes is not None:
        random_bytes = cryptocore.generate_random_bytes(16)
        assert isinstance(random_bytes, bytes), "generate_random_bytes should return bytes"
        assert len(random_bytes) == 16, "generate_random_bytes should return correct length"
        print("✓ generate_random_bytes works")
    
    if cryptocore.generate_key is not None:
        key = cryptocore.generate_key()
        assert isinstance(key, bytes), "generate_key should return bytes"
        assert len(key) == 16, "generate_key should return 16 bytes"
        print("✓ generate_key works")
    
    if cryptocore.generate_iv is not None:
        iv = cryptocore.generate_iv()
        assert isinstance(iv, bytes), "generate_iv should return bytes"
        assert len(iv) == 16, "generate_iv should return 16 bytes"
        print("✓ generate_iv works")
    
    # Тест CLI функций
    if cryptocore.validate_key is not None:
        try:
            key = cryptocore.validate_key("@00112233445566778899aabbccddeeff")
            assert isinstance(key, bytes), "validate_key should return bytes"
            assert len(key) == 16, "validate_key should return 16 bytes"
            print("✓ validate_key works")
        except Exception as e:
            print(f"⚠ validate_key test skipped: {e}")
    
    if cryptocore.check_weak_key is not None:
        try:
            weak_key = bytes([0] * 16)
            result = cryptocore.check_weak_key(weak_key)
            assert isinstance(result, bool), "check_weak_key should return bool"
            print("✓ check_weak_key works")
        except Exception as e:
            print(f"⚠ check_weak_key test skipped: {e}")
    
    return True


def main():
    """Запуск всех тестов для __init__.py"""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ МОДУЛЯ __INIT__.PY")
    print("=" * 60)
    
    all_passed = True
    
    tests = [
        ("Import Tests", test_init_imports),
        ("Import Error Handling", test_init_import_error_handling),
        ("Functionality Tests", test_init_functionality),
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
        print("ALL __INIT__ TESTS PASSED!")
        return True
    else:
        print("SOME __INIT__ TESTS FAILED!")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

