
import sys
import os
import time

# Добавляем путь к src для импорта cryptocore
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from cryptocore.kdf.pbkdf2 import pbkdf2_hmac_sha256, pbkdf2

# ============================================================================
# ТЕСТОВЫЕ ВЕКТОРЫ RFC 6070
# ============================================================================

RFC6070_TEST_CASES = [
    # Test 1: Basic case, 1 iteration
    {
        'password': b'password',
        'salt': b'salt',
        'iterations': 1,
        'dklen': 32,
        'expected': '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'
    },
    # Test 2: 2 iterations
    {
        'password': b'password',
        'salt': b'salt',
        'iterations': 2,
        'dklen': 32,
        'expected': 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43'
    },
    # Test 3: 4096 iterations
    {
        'password': b'password',
        'salt': b'salt',
        'iterations': 4096,
        'dklen': 32,
        'expected': 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'
    },
    # Test 4: Longer password and salt
    {
        'password': b'passwordPASSWORDpassword',
        'salt': b'saltSALTsaltSALTsaltSALTsaltSALTsalt',
        'iterations': 4096,
        'dklen': 40,
        'expected': '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9'
    },
    # Test 5: Null characters in password and salt
    {
        'password': b'pass\x00word',
        'salt': b'sa\x00lt',
        'iterations': 4096,
        'dklen': 16,
        'expected': '89b69d0516f829893c696226650a8687'
    }
]


def test_rfc6070_vectors():
    print("=" * 60)
    print("Тестирование PBKDF2-HMAC-SHA256 с векторами RFC 6070")
    print("=" * 60)

    all_passed = True
    for i, test_case in enumerate(RFC6070_TEST_CASES, 1):
        try:
            result = pbkdf2_hmac_sha256(
                test_case['password'],
                test_case['salt'],
                test_case['iterations'],
                test_case['dklen']
            )
            result_hex = result.hex()
            expected = test_case['expected']

            if result_hex == expected:
                print(f"✓ Тест {i}: Пройден (итераций: {test_case['iterations']})")
            else:
                print(f"✗ Тест {i}: Не пройден")
                print(f"  Ожидалось: {expected}")
                print(f"  Получено:  {result_hex}")
                all_passed = False

        except Exception as e:
            print(f"✗ Тест {i}: Ошибка - {e}")
            all_passed = False

    print("-" * 60)
    if all_passed:
        print("✓ Все тесты RFC 6070 пройдены успешно!")
    else:
        print("✗ Некоторые тесты RFC 6070 не пройдены")

    return all_passed


def test_pbkdf2_functionality():

    print("\n" + "=" * 60)
    print("Функциональное тестирование PBKDF2")
    print("=" * 60)

    tests_passed = 0
    total_tests = 5

    # Тест 1: Детерминированность
    try:
        key1 = pbkdf2_hmac_sha256(b'test', b'salt', 1000, 32)
        key2 = pbkdf2_hmac_sha256(b'test', b'salt', 1000, 32)
        assert key1 == key2, "Результат не детерминирован"
        print("✓ Тест 1: Результат детерминирован")
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ Тест 1: {e}")

    # Тест 2: Разные длины ключей
    try:
        lengths = [1, 16, 32, 64, 100]
        for length in lengths:
            key = pbkdf2_hmac_sha256(b'test', b'salt', 100, length)
            assert len(key) == length, f"Неверная длина: {len(key)} вместо {length}"
        print("✓ Тест 2: Поддерживаются разные длины ключей (1-100 байт)")
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ Тест 2: {e}")

    # Тест 3: Разные итерации дают разные ключи
    try:
        key1 = pbkdf2_hmac_sha256(b'test', b'salt', 100, 32)
        key2 = pbkdf2_hmac_sha256(b'test', b'salt', 1000, 32)
        assert key1 != key2, "Разные итерации должны давать разные ключи"
        print("✓ Тест 3: Разные итерации дают разные ключи")
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ Тест 3: {e}")

    # Тест 4: Разные соли дают разные ключи
    try:
        key1 = pbkdf2_hmac_sha256(b'test', b'salt1', 100, 32)
        key2 = pbkdf2_hmac_sha256(b'test', b'salt2', 100, 32)
        assert key1 != key2, "Разные соли должны давать разные ключи"
        print("✓ Тест 4: Разные соли дают разные ключи")
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ Тест 4: {e}")

    # Тест 5: Разные пароли дают разные ключи
    try:
        key1 = pbkdf2_hmac_sha256(b'password1', b'salt', 100, 32)
        key2 = pbkdf2_hmac_sha256(b'password2', b'salt', 100, 32)
        assert key1 != key2, "Разные пароли должны давать разные ключи"
        print("✓ Тест 5: Разные пароли дают разные ключи")
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ Тест 5: {e}")

    print("-" * 60)
    print(f"Функциональные тесты: {tests_passed}/{total_tests} пройдено")

    return tests_passed == total_tests


def test_interoperability_openssl():
    print("\n" + "=" * 60)
    print("Проверка совместимости с OpenSSL")
    print("=" * 60)

    try:
        import subprocess
        import binascii
        import tempfile
        import os

        # Проверяем наличие OpenSSL
        result = subprocess.run(['openssl', 'version'], capture_output=True, text=True)
        if result.returncode != 0:
            print("✗ OpenSSL не найден")
            return False

        openssl_version = result.stdout.strip()
        print(f"Используется: {openssl_version}")

        test_cases = [
            {
                'name': 'Тест 1: Простая проверка',
                'password': 'test',
                'salt_hex': '1234567890abcdef',
                'iterations': 1000,
                'dklen': 32,
                'salt_bytes': binascii.unhexlify('1234567890abcdef')
            },
            {
                'name': 'Тест 2: Длинный пароль',
                'password': 'password123',
                'salt_hex': 'aabbccddeeff00112233445566778899',
                'iterations': 5000,
                'dklen': 16,
                'salt_bytes': binascii.unhexlify('aabbccddeeff00112233445566778899')
            }
        ]

        all_passed = True

        for i, test in enumerate(test_cases, 1):
            print(f"\n{test['name']}:")
            print(f"  Пароль:    {test['password']}")
            print(f"  Соль:      {test['salt_hex']}")
            print(f"  Итерации:  {test['iterations']}")
            print(f"  Длина:     {test['dklen']} байт")

            # 1. Получаем ключ нашей реализацией
            our_key = pbkdf2(
                test['password'],
                test['salt_hex'],
                test['iterations'],
                test['dklen']
            )
            print(f"  Наш ключ:  {our_key}")

            # 2. Получаем ключ через OpenSSL enc -pbkdf2
            try:
                # Создаем временный файл для пароля
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                    f.write(test['password'])
                    pass_file = f.name

                # Команда OpenSSL (совместимая с реальным использованием)
                cmd = (
                    f'openssl enc -aes-256-cbc '
                    f'-pass pass:{test["password"]} '
                    f'-S {test["salt_hex"]} '
                    f'-iter {test["iterations"]} '
                    f'-pbkdf2 -P -md sha256'
                )

                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                if result.returncode == 0:
                    # Парсим вывод
                    for line in result.stdout.split('\n'):
                        if line.startswith('key='):
                            openssl_key = line.split('=')[1].strip().lower()
                            break
                    else:
                        openssl_key = None

                    if openssl_key:
                        print(f"  OpenSSL:   {openssl_key}")

                        if our_key == openssl_key:
                            print("  ✓ СОВПАДАЕТ С OPENSSL")
                        else:
                            print("  ✗ НЕ СОВПАДАЕТ С OPENSSL")
                            all_passed = False
                    else:
                        print("  ✗ Не удалось получить ключ из OpenSSL")
                        all_passed = False
                else:
                    print(f"  ✗ Ошибка OpenSSL: {result.stderr[:100]}")
                    all_passed = False

                # Удаляем временный файл
                try:
                    os.unlink(pass_file)
                except:
                    pass

            except Exception as e:
                print(f"  ✗ Ошибка выполнения: {e}")
                all_passed = False

        # 3. Проверка с тестовыми векторами OpenSSL
        print("\n" + "-" * 60)
        print("Проверка с известными тестами OpenSSL:")

        # Известный тест: пароль "password", соль "salt", 1 итерация
        test_vector = {
            'password': 'password',
            'salt_bytes': b'salt',
            'iterations': 1,
            'dklen': 32
        }

        print(f"\nТестовый вектор OpenSSL:")
        print(f"  Пароль:    {test_vector['password']}")
        print(f"  Соль:      {binascii.hexlify(test_vector['salt_bytes']).decode()}")
        print(f"  Итерации:  {test_vector['iterations']}")

        # Наш результат
        our_key = pbkdf2(
            test_vector['password'],
            binascii.hexlify(test_vector['salt_bytes']).decode(),
            test_vector['iterations'],
            test_vector['dklen']
        )
        print(f"  Наш ключ:  {our_key}")

        # Ожидаемый результат от OpenSSL (из RFC 6070 и проверенный)
        expected_openssl = '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'
        print(f"  Ожидаемый: {expected_openssl}")

        if our_key == expected_openssl:
            print("  ✓ НАША РЕАЛИЗАЦИЯ СООТВЕТСТВУЕТ OPENSSL/RFC 6070")
        else:
            print("  ✗ НАША РЕАЛИЗАЦИЯ НЕ СООТВЕТСТВУЕТ OPENSSL/RFC 6070")
            all_passed = False

        print("\n" + "=" * 60)
        if all_passed:
            print("✓ СОВМЕСТИМОСТЬ С OPENSSL ПОДТВЕРЖДЕНА")
        else:
            print("✗ ПРОБЛЕМЫ С СОВМЕСТИМОСТЬЮ OPENSSL")

        return all_passed

    except Exception as e:
        print(f" Проверка OpenSSL пропущена: {e}")
        return False


def test_pbkdf2_error_handling():
    """Тест обработки ошибок в PBKDF2"""
    print("\n" + "=" * 60)
    print("Тестирование обработки ошибок PBKDF2")
    print("=" * 60)
    
    from cryptocore.kdf.pbkdf2 import pbkdf2_hmac_sha256, pbkdf2
    
    password = b"password"
    salt = b"salt"
    
    # Тест с dklen <= 0
    try:
        pbkdf2_hmac_sha256(password, salt, iterations=1, dklen=0)
        assert False, "Should raise ValueError for dklen <= 0"
    except ValueError as e:
        assert "положительным" in str(e).lower() or "positive" in str(e).lower()
        print("✓ ValueError raised for dklen <= 0")
    
    # Тест с iterations <= 0
    try:
        pbkdf2_hmac_sha256(password, salt, iterations=0, dklen=16)
        assert False, "Should raise ValueError for iterations <= 0"
    except ValueError as e:
        assert "положительным" in str(e).lower() or "positive" in str(e).lower()
        print("✓ ValueError raised for iterations <= 0")
    
    # Тест pbkdf2 с password как bytes (не строка)
    result = pbkdf2(password, salt.hex(), iterations=1, dklen=16)
    assert isinstance(result, str), "Should return hex string"
    assert len(result) == 32, "Should return correct length (16 bytes = 32 hex chars)"
    print("✓ pbkdf2 works with bytes password")
    
    # Тест pbkdf2 с salt_hex как bytes (не строка)
    result = pbkdf2("password", salt, iterations=1, dklen=16)
    assert isinstance(result, str), "Should return hex string"
    print("✓ pbkdf2 works with bytes salt")
    
    # Тест pbkdf2 с salt_hex как строка (не hex)
    result = pbkdf2("password", "not_hex_salt", iterations=1, dklen=16)
    assert isinstance(result, str), "Should return hex string"
    print("✓ pbkdf2 works with non-hex string salt")
    
    return True


def main():
    print("Запуск тестов PBKDF2-HMAC-SHA256")
    print()

    all_passed = True

    # Запуск тестов
    if not test_rfc6070_vectors():
        all_passed = False

    if not test_pbkdf2_functionality():
        all_passed = False

    if not test_pbkdf2_error_handling():
        all_passed = False

    test_interoperability_openssl()

    print("\n" + "=" * 60)
    if all_passed:
        print(" ВСЕ ТЕСТЫ PBKDF2 ПРОЙДЕНЫ УСПЕШНО!")
    else:
        print(" НЕКОТОРЫЕ ТЕСТЫ PBKDF2 НЕ ПРОЙДЕНЫ")
    print("=" * 60)

    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())