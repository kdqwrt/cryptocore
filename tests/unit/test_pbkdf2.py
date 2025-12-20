
import sys
import os
import time


sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

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
        import tempfile

        test_cases = [
            {
                'password': 'test',
                'salt': '1234567890abcdef',
                'iterations': 1000,
                'length': 32
            },
            {
                'password': 'password123',
                'salt': 'aabbccddeeff00112233445566778899',
                'iterations': 5000,
                'length': 16
            }
        ]

        for i, test in enumerate(test_cases, 1):
            # Получаем ключ нашей реализацией
            our_key_hex = pbkdf2(
                test['password'],
                test['salt'],
                test['iterations'],
                test['length']
            )

            # Формируем команду OpenSSL
            cmd = [
                'openssl', 'kdf', '-keylen', str(test['length']),
                '-kdfopt', f'pass:{test["password"]}',
                '-kdfopt', f'salt:{test["salt"]}',
                '-kdfopt', f'iter:{test["iterations"]}',
                'PBKDF2'
            ]

            # Запускаем OpenSSL
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                openssl_key = result.stdout.strip().replace(':', '')

                if our_key_hex == openssl_key:
                    print(f"✓ Тест {i}: Совместимость с OpenSSL подтверждена")
                else:
                    print(f"✗ Тест {i}: Несовместимость с OpenSSL")
                    print(f"  Наш ключ:    {our_key_hex}")
                    print(f"  OpenSSL ключ: {openssl_key}")
            else:
                print(f"Тест {i}: OpenSSL не установлен или ошибка выполнения")
                print(f"  Ошибка: {result.stderr}")

    except Exception as e:
        print(f" Проверка OpenSSL пропущена: {e}")


def main():
    print("Запуск тестов PBKDF2-HMAC-SHA256")
    print()

    all_passed = True

    # Запуск тестов
    if not test_rfc6070_vectors():
        all_passed = False

    if not test_pbkdf2_functionality():
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