import sys
import os
import tempfile
import subprocess

# Добавляем путь к src
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from cryptocore.mac.hmac import HMAC

    HAS_HMAC = True
except ImportError:
    HAS_HMAC = False
    print("HMAC module not found. Skipping tests.")
    sys.exit(1)


def test_rfc4231_vectors():
    print("\n" + "=" * 60)
    print("TEST-1: Тестовые векторы RFC 4231")
    print("=" * 60)

    test_cases = [
        # Тестовый случай 1
        {
            'key': bytes([0x0b] * 20),
            'data': b"Hi There",
            'expected': "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        },
        # Тестовый случай 2
        {
            'key': b"Jefe",
            'data': b"what do ya want for nothing?",
            'expected': "5bdcc146bf89754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        },
        # Тестовый случай 3
        {
            'key': bytes([0xaa] * 20),
            'data': bytes([0xdd] * 50),
            'expected': "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        },
        # Тестовый случай 4
        {
            'key': bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
            'data': bytes([0xcd] * 50),
            'expected': "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        }
    ]

    passed = 0
    for i, test in enumerate(test_cases, 1):
        hmac = HMAC(test['key'], 'sha256')
        result = hmac.hexdigest(test['data'])

        if result == test['expected']:
            print(f"✓ Тестовый случай {i} пройден")
            passed += 1
        else:
            print(f"✗ Тестовый случай {i} не пройден")
            print(f"  Ожидалось: {test['expected']}")
            print(f"  Получено:  {result}")

    print(f"\nРезультат: {passed}/{len(test_cases)} тестовых случаев пройдено")
    return passed == len(test_cases)


def test_verification():

    print("\n" + "=" * 60)
    print("TEST-2: Тест проверки (самогенерация + верификация)")
    print("=" * 60)

    key = b"00112233445566778899aabbccddeeff"
    data = b"Test message for HMAC verification"

    # Создаем временный файл с данными
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(data)
        data_file = f.name

    # Создаем временный файл для HMAC
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hmac') as f:
        hmac_file = f.name

    try:
        # Шаг 1: Генерируем HMAC через CLI
        gen_result = subprocess.run(
            [sys.executable, '-m', 'cryptocore.cli', 'dgst',
             '--algorithm', 'sha256',
             '--hmac',
             '--key', key.hex(),
             '--input', data_file,
             '--output', hmac_file],
            capture_output=True,
            text=True
        )

        if gen_result.returncode != 0:
            print(f"✗ Генерация HMAC не удалась: {gen_result.stderr}")
            return False

        print("✓ HMAC успешно сгенерирован")

        # Шаг 2: Проверяем HMAC через CLI
        verify_result = subprocess.run(
            [sys.executable, '-m', 'cryptocore.cli', 'dgst',
             '--algorithm', 'sha256',
             '--hmac',
             '--key', key.hex(),
             '--input', data_file,
             '--verify', hmac_file],
            capture_output=True,
            text=True
        )

        if verify_result.returncode == 0:
            print("✓ HMAC верификация успешна")
            return True
        else:
            print(f"✗ HMAC верификация не удалась: {verify_result.stderr}")
            return False

    finally:
        # Очистка
        os.unlink(data_file)
        os.unlink(hmac_file)


def test_file_tamper_detection():
    print("\n" + "=" * 60)
    print("TEST-3: Обнаружение изменений файла")
    print("=" * 60)

    key = b"secret_key_for_tamper_test"

    # Оригинальные данные
    original_data = b"Original secret message that should not be modified"

    # Измененные данные (меняем один байт)
    tampered_data = original_data[:-1] + b"X"  # Изменен последний байт

    # Создаем два файла
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(original_data)
        original_file = f.name

    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(tampered_data)
        tampered_file = f.name

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        hmac_file = f.name

    try:
        # Шаг 1: Генерируем HMAC для оригинального файла
        gen_result = subprocess.run(
            [sys.executable, '-m', 'cryptocore.cli', 'dgst',
             '--algorithm', 'sha256',
             '--hmac',
             '--key', key.hex(),
             '--input', original_file,
             '--output', hmac_file],
            capture_output=True,
            text=True
        )

        if gen_result.returncode != 0:
            print(f"✗ Генерация HMAC не удалась: {gen_result.stderr}")
            return False

        print("✓ HMAC для оригинального файла сгенерирован")

        # Шаг 2: Пытаемся проверить HMAC с измененным файлом
        verify_result = subprocess.run(
            [sys.executable, '-m', 'cryptocore.cli', 'dgst',
             '--algorithm', 'sha256',
             '--hmac',
             '--key', key.hex(),
             '--input', tampered_file,
             '--verify', hmac_file],
            capture_output=True,
            text=True
        )

        # Должно завершиться с ошибкой (код возврата != 0)
        if verify_result.returncode != 0:
            print("✓ Изменение файла успешно обнаружено")
            return True
        else:
            print("✗ Изменение файла не обнаружено (должно было завершиться с ошибкой)")
            return False

    finally:
        # Очистка
        os.unlink(original_file)
        os.unlink(tampered_file)
        os.unlink(hmac_file)


def test_wrong_key_detection():
    print("\n" + "=" * 60)
    print("TEST-4: Обнаружение изменений ключа")
    print("=" * 60)

    correct_key = b"correct_key_1234567890"
    wrong_key = b"wrong_key_0987654321"
    data = b"Test data for key sensitivity"

    # Создаем файл с данными
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(data)
        data_file = f.name

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        hmac_file = f.name

    try:
        # Шаг 1: Генерируем HMAC с правильным ключом
        gen_result = subprocess.run(
            [sys.executable, '-m', 'cryptocore.cli', 'dgst',
             '--algorithm', 'sha256',
             '--hmac',
             '--key', correct_key.hex(),
             '--input', data_file,
             '--output', hmac_file],
            capture_output=True,
            text=True
        )

        if gen_result.returncode != 0:
            print(f"✗ Генерация HMAC не удалась: {gen_result.stderr}")
            return False

        print("✓ HMAC с правильным ключом сгенерирован")

        # Шаг 2: Пытаемся проверить с неправильным ключом
        verify_result = subprocess.run(
            [sys.executable, '-m', 'cryptocore.cli', 'dgst',
             '--algorithm', 'sha256',
             '--hmac',
             '--key', wrong_key.hex(),
             '--input', data_file,
             '--verify', hmac_file],
            capture_output=True,
            text=True
        )

        # Должно завершиться с ошибкой (код возврата != 0)
        if verify_result.returncode != 0:
            print("✓ Неправильный ключ успешно обнаружен")
            return True
        else:
            print("✗ Неправильный ключ не обнаружен (должно было завершиться с ошибкой)")
            return False

    finally:
        # Очистка
        os.unlink(data_file)
        os.unlink(hmac_file)


def test_key_size_handling():
    print("\n" + "=" * 60)
    print("TEST-5: Тесты размера ключа")
    print("=" * 60)

    data = b"Test data for key size testing"

    test_keys = [
        (b"short16", "Короткий ключ (7 байт)"),
        (b"exactly_16_bytes!!", "Ключ 16 байт"),
        (b"x" * 64, "Ключ 64 байта (размер блока)"),
        (b"y" * 100, "Ключ 100 байт (длиннее блока)"),
    ]

    passed = 0
    for key, description in test_keys:
        try:
            hmac = HMAC(key, 'sha256')
            result = hmac.hexdigest(data)

            # Проверяем, что HMAC вычислен (64 символа hex = 32 байта)
            if len(result) == 64:
                print(f"✓ {description}: успешно")
                passed += 1
            else:
                print(f"✗ {description}: неверная длина HMAC")

        except Exception as e:
            print(f"✗ {description}: ошибка - {e}")

    print(f"\nРезультат: {passed}/{len(test_keys)} тестов ключей пройдено")
    return passed == len(test_keys)


def test_empty_file():
    print("\n" + "=" * 60)
    print("TEST-6: Тест пустого файла")
    print("=" * 60)

    key = b"key_for_empty_file_test"

    # Создаем пустой файл
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        # Файл остается пустым
        empty_file = f.name

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        hmac_output = f.name

    try:
        # Генерируем HMAC для пустого файла
        result = subprocess.run(
            [sys.executable, '-m', 'cryptocore.cli', 'dgst',
             '--algorithm', 'sha256',
             '--hmac',
             '--key', key.hex(),
             '--input', empty_file,
             '--output', hmac_output],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"✗ Ошибка при вычислении HMAC для пустого файла: {result.stderr}")
            return False

        # Проверяем, что файл создан и содержит валидный HMAC
        if not os.path.exists(hmac_output):
            print("✗ Файл с HMAC не создан")
            return False

        with open(hmac_output, 'r') as f:
            content = f.read().strip()

        # Проверяем формат вывода: HMAC_VALUE ИМЯ_ФАЙЛА
        parts = content.split()
        if len(parts) >= 1:
            hmac_value = parts[0]
            if len(hmac_value) == 64 and all(c in '0123456789abcdefABCDEF' for c in hmac_value):
                print("✓ HMAC для пустого файла успешно вычислен")
                return True
            else:
                print(f"✗ Неверный формат HMAC: {hmac_value}")
                return False
        else:
            print("✗ Пустой вывод")
            return False

    finally:
        # Очистка
        os.unlink(empty_file)
        os.unlink(hmac_output)


def test_large_file():
    print("\n" + "=" * 60)
    print("TEST-7: Тест большого файла")
    print("=" * 60)

    key = b"key_for_large_file_test"

    large_data = b"X" * (5 * 1024 * 1024)  # 5 MB

    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.bin') as f:
        f.write(large_data)
        large_file = f.name

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        hmac_output = f.name

    try:
        # Генерируем HMAC для большого файла с таймаутом
        result = subprocess.run(
            [sys.executable, '-m', 'cryptocore.cli', 'dgst',
             '--algorithm', 'sha256',
             '--hmac',
             '--key', key.hex(),
             '--input', large_file,
             '--output', hmac_output],
            capture_output=True,
            text=True,
            timeout=30  # 30 секунд должно хватить для 5 MB
        )

        if result.returncode != 0:
            print(f"✗ Ошибка при вычислении HMAC для большого файла: {result.stderr}")
            return False

        # Проверяем результат
        if not os.path.exists(hmac_output):
            print("✗ Файл с HMAC не создан")
            return False

        file_size = os.path.getsize(large_file)
        print(f"✓ HMAC для файла {file_size:,} байт успешно вычислен")
        return True

    except subprocess.TimeoutExpired:
        print("✗ Таймаут при вычислении HMAC для большого файла")
        return False
    finally:
        # Очистка
        if os.path.exists(large_file):
            os.unlink(large_file)
        if os.path.exists(hmac_output):
            os.unlink(hmac_output)


def test_cli_hmac_examples():
    print("\n" + "=" * 60)
    print("Тест примеров из ТЗ")
    print("=" * 60)

    key = b"00112233445566778899aabbccddeeff"
    data = b"Hi There"

    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(data)
        data_file = f.name

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        hmac_file = f.name

    try:
        print("Тестирование: cryptocore dgst --algorithm sha256 --hmac --key <key> --input <file>")
        result = subprocess.run(
            [sys.executable, '-m', 'cryptocore.cli', 'dgst',
             '--algorithm', 'sha256',
             '--hmac',
             '--key', key.hex(),
             '--input', data_file],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"✗ Пример генерации не работает: {result.stderr}")
            return False

        output = result.stdout.strip()

        if len(output.split()) >= 2 and len(output.split()[0]) == 64:
            print(f"✓ Пример генерации работает: {output.split()[0][:16]}...")
        else:
            print(f"✗ Неверный формат вывода: {output}")
            return False

        return True

    finally:
        os.unlink(data_file)
        os.unlink(hmac_file)


def main():

    print("=" * 70)
    print("СПРИНТ 5: ТЕСТИРОВАНИЕ HMAC")
    print("=" * 70)

    if not HAS_HMAC:
        print("ОШИБКА: Модуль HMAC не найден")
        print("Убедитесь, что созданы:")
        print("  src/cryptocore/mac/hmac.py")
        print("  src/cryptocore/mac/__init__.py")
        return False

    # Запускаем все тесты
    tests = [
        ("RFC 4231 тестовые векторы", test_rfc4231_vectors),
        ("Проверка самогенерации", test_verification),
        ("Обнаружение изменений файла", test_file_tamper_detection),
        ("Обнаружение неправильного ключа", test_wrong_key_detection),
        ("Тесты размера ключа", test_key_size_handling),
        ("Тест пустого файла", test_empty_file),
        ("Тест большого файла", test_large_file),
        ("Примеры из ТЗ", test_cli_hmac_examples),
    ]

    results = []

    for test_name, test_func in tests:
        print(f"\nЗапуск: {test_name}")
        try:
            success = test_func()
            results.append((test_name, success))

            if success:
                print(f"✅ {test_name}: ПРОЙДЕН")
            else:
                print(f"❌ {test_name}: НЕ ПРОЙДЕН")

        except Exception as e:
            print(f"⚠️  {test_name}: ОШИБКА - {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))

    # Выводим итоговую сводку
    print("\n" + "=" * 70)
    print("ИТОГОВАЯ СВОДКА СПРИНТ 5")
    print("=" * 70)

    passed = sum(1 for _, success in results if success)
    total = len(results)

    for test_name, success in results:
        status = "✅ ПРОЙДЕН" if success else "❌ НЕ ПРОЙДЕН"
        print(f"{status}: {test_name}")

    print(f"\nВсего тестов: {total}")
    print(f"Пройдено: {passed}")
    print(f"Не пройдено: {total - passed}")

    if passed == total:
        print("\n🎉 ВСЕ ТЕСТЫ СПРИНТА 5 УСПЕШНО ПРОЙДЕНЫ!")
    else:
        print(f"\n⚠️  {total - passed} тестов не пройдено")

    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)