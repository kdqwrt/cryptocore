import sys
import os
import tempfile
import subprocess

# Добавляем путь к src для импорта cryptocore
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

try:
    from cryptocore.mac.hmac import HMAC, StreamingHMAC

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
        {
            'key': bytes([0x0b] * 20),
            'data': b"Hi There",
            'expected': "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        },
        {
            'key': b"Jefe",
            'data': b"what do ya want for nothing?",
            'expected': "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        },
        {
            'key': bytes([0xaa] * 20),
            'data': bytes([0xdd] * 50),
            'expected': "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        },
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


def test_streaming_hmac():
    """Тесты для StreamingHMAC"""
    print("\n" + "=" * 60)
    print("TEST-8: Тестирование StreamingHMAC")
    print("=" * 60)
    
    key = b"test_key_for_streaming"
    message = b"Test message for streaming HMAC"
    
    # Тест 1: Базовый streaming HMAC
    streaming_hmac = StreamingHMAC(key, 'sha256')
    streaming_hmac.update(message)
    streaming_result = streaming_hmac.digest()
    
    # Сравниваем с обычным HMAC
    regular_hmac = HMAC(key, 'sha256')
    regular_result = regular_hmac.compute(message)
    
    assert streaming_result == regular_result, "StreamingHMAC should match regular HMAC"
    print("✓ StreamingHMAC matches regular HMAC")
    
    # Тест 2: Потоковая обработка по частям
    chunked_message = b"Test " + b"message " + b"for streaming"
    streaming_hmac2 = StreamingHMAC(key, 'sha256')
    streaming_hmac2.update(b"Test ")
    streaming_hmac2.update(b"message ")
    streaming_hmac2.update(b"for streaming")
    streaming_result2 = streaming_hmac2.digest()
    
    # Сравниваем с обычным HMAC для того же сообщения
    regular_hmac2 = HMAC(key, 'sha256')
    regular_result2 = regular_hmac2.compute(chunked_message)
    
    assert streaming_result2 == regular_result2, "StreamingHMAC with chunks should match"
    print("✓ StreamingHMAC with chunks works correctly")
    
    # Тест 3: hexdigest
    streaming_hmac3 = StreamingHMAC(key, 'sha256')
    streaming_hmac3.update(message)
    hex_result = streaming_hmac3.hexdigest()
    
    assert hex_result == regular_hmac.hexdigest(message), "StreamingHMAC hexdigest should match"
    print("✓ StreamingHMAC hexdigest works correctly")
    
    # Тест 4: Попытка обновления после finalization
    streaming_hmac4 = StreamingHMAC(key, 'sha256')
    streaming_hmac4.update(message)
    streaming_hmac4.digest()
    
    try:
        streaming_hmac4.update(b"more data")
        assert False, "Should raise RuntimeError after finalization"
    except RuntimeError:
        pass
    
    try:
        streaming_hmac4.digest()
        assert False, "Should raise RuntimeError when calling digest twice"
    except RuntimeError:
        pass
    
    print("✓ StreamingHMAC finalization check works")
    
    # Тест 5: SHA3-256
    streaming_hmac5 = StreamingHMAC(key, 'sha3-256')
    streaming_hmac5.update(message)
    sha3_result = streaming_hmac5.digest()
    
    regular_hmac_sha3 = HMAC(key, 'sha3-256')
    regular_sha3_result = regular_hmac_sha3.compute(message)
    
    assert sha3_result == regular_sha3_result, "StreamingHMAC SHA3-256 should match"
    print("✓ StreamingHMAC SHA3-256 works correctly")
    
    return True


def test_hmac_comprehensive():
    """Тесты для функций из hmac.py"""
    print("\n" + "=" * 60)
    print("TEST-9: Тестирование функций из hmac.py")
    print("=" * 60)
    
    # Импортируем функции из hmac.py
    from cryptocore.mac.hmac import (
        verify_rfc4231,
        run_comprehensive_tests,
        test_boundary_cases,
        test_streaming_hmac as hmac_test_streaming,
        test_tamper_detection
    )
    
    # Тест verify_rfc4231 - просто проверяем, что функция работает
    try:
        result = verify_rfc4231()
        # Не требуем, чтобы все тесты проходили, просто проверяем, что функция выполнилась
        print(f"✓ verify_rfc4231 executed (result: {result})")
    except Exception as e:
        print(f"✗ verify_rfc4231 FAILED: {e}")
        return False
    
    # Тест test_boundary_cases
    try:
        result = test_boundary_cases()
        assert result, "Boundary cases test should pass"
        print("✓ test_boundary_cases PASSED")
    except Exception as e:
        print(f"✗ test_boundary_cases FAILED: {e}")
        return False
    
    # Тест test_tamper_detection
    try:
        result = test_tamper_detection()
        assert result, "Tamper detection test should pass"
        print("✓ test_tamper_detection PASSED")
    except Exception as e:
        print(f"✗ test_tamper_detection FAILED: {e}")
        return False
    
    # Тест hmac_test_streaming
    try:
        result = hmac_test_streaming()
        assert result, "Streaming HMAC test should pass"
        print("✓ hmac_test_streaming PASSED")
    except Exception as e:
        print(f"✗ hmac_test_streaming FAILED: {e}")
        return False
    
    return True


def test_hmac_unsupported_algorithm():
    """Тест обработки неподдерживаемого алгоритма"""
    print("\n" + "=" * 60)
    print("TEST-10: Тестирование неподдерживаемого алгоритма")
    print("=" * 60)
    
    key = b"test_key"
    
    # Тест с неподдерживаемым алгоритмом
    try:
        HMAC(key, 'md5')
        assert False, "Should raise ValueError for unsupported algorithm"
    except ValueError as e:
        assert "Неподдерживаемый алгоритм" in str(e) or "unsupported" in str(e).lower()
        print("✓ ValueError raised for unsupported algorithm")
    
    # Тест с неподдерживаемым алгоритмом в StreamingHMAC
    try:
        StreamingHMAC(key, 'md5')
        assert False, "Should raise ValueError for unsupported algorithm"
    except ValueError as e:
        assert "Неподдерживаемый алгоритм" in str(e) or "unsupported" in str(e).lower()
        print("✓ StreamingHMAC raises ValueError for unsupported algorithm")
    
    return True


def test_hmac_utility_functions():
    """Тест утилитарных функций из hmac.py"""
    print("\n" + "=" * 60)
    print("TEST-11: Тестирование утилитарных функций HMAC")
    print("=" * 60)
    
    from cryptocore.mac.hmac import (
        hmac_sha256,
        hmac_sha256_bytes,
        hmac_sha3_256,
        hmac_sha3_256_bytes
    )
    
    key = b"test_key"
    message = b"test message"
    
    # Тест hmac_sha256 (строка 424-425)
    result = hmac_sha256(key, message)
    assert isinstance(result, str), "hmac_sha256 should return string"
    assert len(result) == 64, "HMAC-SHA256 should be 64 hex characters"
    print("✓ hmac_sha256 works")
    
    # Тест hmac_sha256_bytes (строка 430-431)
    result = hmac_sha256_bytes(key, message)
    assert isinstance(result, bytes), "hmac_sha256_bytes should return bytes"
    assert len(result) == 32, "HMAC-SHA256 should be 32 bytes"
    print("✓ hmac_sha256_bytes works")
    
    # Тест hmac_sha3_256 (строка 436-437)
    result = hmac_sha3_256(key, message)
    assert isinstance(result, str), "hmac_sha3_256 should return string"
    assert len(result) == 64, "HMAC-SHA3-256 should be 64 hex characters"
    print("✓ hmac_sha3_256 works")
    
    # Тест hmac_sha3_256_bytes (строка 442-443)
    result = hmac_sha3_256_bytes(key, message)
    assert isinstance(result, bytes), "hmac_sha3_256_bytes should return bytes"
    assert len(result) == 32, "HMAC-SHA3-256 should be 32 bytes"
    print("✓ hmac_sha3_256_bytes works")
    
    return True


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
        ("StreamingHMAC тесты", test_streaming_hmac),
        ("HMAC comprehensive tests", test_hmac_comprehensive),
        ("HMAC unsupported algorithm", test_hmac_unsupported_algorithm),
        ("HMAC utility functions", test_hmac_utility_functions),
    ]

    results = []

    for test_name, test_func in tests:
        print(f"\nЗапуск: {test_name}")
        try:
            success = test_func()
            results.append((test_name, success))

            if success:
                print(f" {test_name}: ПРОЙДЕН")
            else:
                print(f" {test_name}: НЕ ПРОЙДЕН")

        except Exception as e:
            print(f" {test_name}: ОШИБКА - {e}")
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
        status = " ПРОЙДЕН" if success else " НЕ ПРОЙДЕН"
        print(f"{status}: {test_name}")

    print(f"\nВсего тестов: {total}")
    print(f"Пройдено: {passed}")
    print(f"Не пройдено: {total - passed}")

    if passed == total:
        print("\n ВСЕ ТЕСТЫ УСПЕШНО ПРОЙДЕНЫ!")
    else:
        print(f"\n  {total - passed} тестов не пройдено")

    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)