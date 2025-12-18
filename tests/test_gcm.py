import os
import sys
import tempfile
import subprocess
from pathlib import Path


sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from cryptocore.modes.gcm import GCM, AuthenticationError
    from cryptocore.aead import EncryptThenMAC, AuthenticationError as AEADAuthError
    from cryptocore.csprng import generate_random_bytes

    HAS_AEAD = True
except ImportError as e:
    print(f"ERROR: AEAD modules not found: {e}")
    print("Make sure you have created:")
    print("  src/cryptocore/modes/gcm.py")
    print("  src/cryptocore/aead.py")
    HAS_AEAD = False


def print_test_header(test_name):
    print("\n" + "=" * 60)
    print(f"TEST: {test_name}")
    print("=" * 60)


# ============================================================================
# TEST-1: Тестовые векторы NIST SP 800-38D
# ============================================================================
def test_nist_test_vectors():
    print_test_header("Тестовые векторы NIST SP 800-38D")

    if not HAS_AEAD:
        print("SKIP: AEAD modules not available")
        return False

    test_vectors = [
        {
            'key': bytes.fromhex('00000000000000000000000000000000'),
            'nonce': bytes.fromhex('000000000000000000000000'),
            'plaintext': b'',
            'aad': b'',
            'expected_ciphertext': b'',
            'expected_tag': bytes.fromhex('58e2fccefa7e3061367f1d57a4e7455a')
        },
        {
            'key': bytes.fromhex('feffe9928665731c6d6a8f9467308308'),
            'nonce': bytes.fromhex('cafebabefacedbaddecaf888'),
            'plaintext': bytes.fromhex('d9313225f88406e5a55909c5aff5269a' +
                                       '86a7a9531534f7da2e4c303d8a318a72' +
                                       '1c3c0c95956809532fcf0e2449a6b525' +
                                       'b16aedf5aa0de657ba637b391aafd255'),
            'aad': bytes.fromhex(''),
            'expected_ciphertext': bytes.fromhex('42831ec2217774244b7221b784d0d49' +
                                                 'ce3aa212f2c02a4e035c17e2329aca1' +
                                                 '2e21d514b25466931c7d8f6a5aac84a' +
                                                 'a051ba30b396a0aac973d58e091473f' +
                                                 '5985'),
            'expected_tag': bytes.fromhex('4d5c2af327cd64a62cf35abd2ba6fab4')
        }
    ]

    passed = 0
    for i, vector in enumerate(test_vectors, 1):
        try:
            gcm = GCM(vector['key'], vector['nonce'])
            result = gcm.encrypt(vector['plaintext'], vector['aad'])

            ciphertext_tag = result[len(vector['nonce']):]
            expected = vector['expected_ciphertext'] + vector['expected_tag']

            if ciphertext_tag == expected:
                print(f"✓ Тестовый вектор {i} пройден")
                passed += 1
            else:
                print(f"✗ Тестовый вектор {i} не пройден")
                print(f"  Ожидалось: {expected.hex()}")
                print(f"  Получено:  {ciphertext_tag.hex()}")

        except Exception as e:
            print(f"✗ Тестовый вектор {i} ошибка: {e}")

    print(f"\nРезультат: {passed}/{len(test_vectors)} тестовых векторов пройдено")
    return passed == len(test_vectors)


# ============================================================================
# TEST-2
# ============================================================================
def test_roundtrip():

    print_test_header("Круговой тест шифрование-расшифрование")

    if not HAS_AEAD:
        print("SKIP: AEAD modules not available")
        return False

    test_cases = [
        (b"Hello GCM world", b""),
        (b"Test with AAD", b"Additional authenticated data"),
        (b"", b"Only AAD no plaintext"),
        (b"X" * 100, b"AAD for 100 byte message"),
    ]

    passed = 0
    for plaintext, aad in test_cases:
        key = generate_random_bytes(16)

        try:
            # Шифрование
            gcm = GCM(key)
            ciphertext = gcm.encrypt(plaintext, aad)

            # Расшифрование
            gcm2 = GCM(key, gcm.nonce)
            decrypted = gcm2.decrypt(ciphertext, aad)

            if decrypted == plaintext:
                print(f"✓ Пройден: {len(plaintext)} байт plaintext, {len(aad)} байт AAD")
                passed += 1
            else:
                print(f"✗ Не пройден: {len(plaintext)} байт plaintext, {len(aad)} байт AAD")

        except Exception as e:
            print(f"✗ Ошибка: {len(plaintext)} байт plaintext - {e}")

    print(f"\nРезультат: {passed}/{len(test_cases)} тестов пройдено")
    return passed == len(test_cases)


# ============================================================================
# TEST-3: Тест на подмену AAD
# ============================================================================
def test_aad_tamper():

    print_test_header("Тест на подмену AAD")

    if not HAS_AEAD:
        print("SKIP: AEAD modules not available")
        return False

    test_cases = [
        (b"Secret message", b"correct_aad", b"wrong_aad"),
        (b"", b"aad", b"different_aad"),
        (b"Test", b"", b"some_aad"),
    ]

    passed = 0
    for plaintext, correct_aad, wrong_aad in test_cases:
        key = generate_random_bytes(16)

        try:
            # Шифрование с верным AAD
            gcm = GCM(key)
            ciphertext = gcm.encrypt(plaintext, correct_aad)

            # Попытка расшифрования с неверным AAD
            gcm2 = GCM(key, gcm.nonce)

            try:
                result = gcm2.decrypt(ciphertext, wrong_aad)
                print(f"✗ Не пройден: должна была быть ошибка аутентификации")
                print(f"  Plaintext: {len(plaintext)} байт, AAD: {correct_aad} -> {wrong_aad}")
                continue
            except AuthenticationError:

                if 'result' in locals():
                    print(f"✗ Не пройден: результат был возвращен несмотря на ошибку")
                    continue

                print(f"✓ Пройден: ошибка аутентификации для неверного AAD")
                passed += 1

        except Exception as e:
            print(f"✗ Ошибка: {e}")

    print(f"\nРезультат: {passed}/{len(test_cases)} тестов пройдено")
    return passed == len(test_cases)


# ============================================================================
# TEST-4: Тест на подмену шифртекста
# ============================================================================
def test_ciphertext_tamper():

    print_test_header("Тест на подмену шифртекста и тега")

    if not HAS_AEAD:
        print("SKIP: AEAD modules not available")
        return False


    key = generate_random_bytes(16)
    plaintext = b"Message to test tamper detection"
    aad = b"associated_data"

    try:

        gcm = GCM(key)
        ciphertext = gcm.encrypt(plaintext, aad)


        tampered = bytearray(ciphertext)
        tampered[20] ^= 0x01

        gcm2 = GCM(key, gcm.nonce)

        try:
            result = gcm2.decrypt(bytes(tampered), aad)
            print("✗ Не пройден: подмена шифртекста не обнаружена")
            return False
        except AuthenticationError:
            print("✓ Пройден: подмена шифртекста обнаружена")


        tampered_tag = bytearray(ciphertext)
        tampered_tag[-1] ^= 0x01  # Изменяем последний байт тега

        gcm3 = GCM(key, gcm.nonce)

        try:
            result = gcm3.decrypt(bytes(tampered_tag), aad)
            print("✗ Не пройден: подмена тега не обнаружена")
            return False
        except AuthenticationError:
            print("✓ Пройден: подмена тега обнаружена")

        return True

    except Exception as e:
        print(f"✗ Ошибка: {e}")
        return False


# ============================================================================
# TEST-5: Тест на повторное использование nonce
# ============================================================================
def test_nonce_uniqueness():
    print_test_header("Тест уникальности nonce")

    if not HAS_AEAD:
        print("SKIP: AEAD modules not available")
        return False

    key = generate_random_bytes(16)
    plaintext = b"Test message"
    aad = b""

    nonces = set()

    try:
        for i in range(1000):
            gcm = GCM(key)
            nonces.add(gcm.nonce)

            # Проверяем, что nonce 12 байт
            if len(gcm.nonce) != 12:
                print(f"✗ Не пройден: nonce должен быть 12 байт, получено {len(gcm.nonce)}")
                return False


            _ = gcm.encrypt(plaintext, aad)

        if len(nonces) == 1000:
            print(f"✓ Пройден: все 1000 nonce уникальны")
            return True
        else:
            print(f"✗ Не пройден: только {len(nonces)} уникальных nonce из 1000")
            return False

    except Exception as e:
        print(f"✗ Ошибка: {e}")
        return False


# ============================================================================
# TEST-6: Тест с пустым AAD
# ============================================================================
def test_empty_aad():
    print_test_header("Тест с пустым AAD")

    if not HAS_AEAD:
        print("SKIP: AEAD modules not available")
        return False

    test_cases = [
        (b"Message with empty AAD", b""),
        (b"", b""),
        (b"X" * 50, b""),
    ]

    passed = 0
    for plaintext, aad in test_cases:
        key = generate_random_bytes(16)

        try:
            gcm = GCM(key)
            ciphertext = gcm.encrypt(plaintext, aad)

            gcm2 = GCM(key, gcm.nonce)
            decrypted = gcm2.decrypt(ciphertext, aad)

            if decrypted == plaintext:
                print(f"✓ Пройден: {len(plaintext)} байт plaintext, пустой AAD")
                passed += 1
            else:
                print(f"✗ Не пройден: {len(plaintext)} байт plaintext, пустой AAD")

        except Exception as e:
            print(f"✗ Ошибка: {e}")

    print(f"\nРезультат: {passed}/{len(test_cases)} тестов пройдено")
    return passed == len(test_cases)


# ============================================================================
# TEST-7: Тест с большим AAD
# ============================================================================
def test_large_aad():
    print_test_header("Тест с большим AAD")

    if not HAS_AEAD:
        print("SKIP: AEAD modules not available")
        return False

    large_aad = b"X" * (5 * 1024 * 1024)  # 5MB

    key = generate_random_bytes(16)
    plaintext = b"Short message with large AAD"

    try:
        print(f"Размер AAD: {len(large_aad):,} байт ({len(large_aad) / 1024 / 1024:.1f} MB)")


        gcm = GCM(key)
        ciphertext = gcm.encrypt(plaintext, large_aad)

        gcm2 = GCM(key, gcm.nonce)
        decrypted = gcm2.decrypt(ciphertext, large_aad)

        if decrypted == plaintext:
            print("✓ Пройден: большой AAD обработан корректно")
            return True
        else:
            print("✗ Не пройден: большой AAD не обработан корректно")
            return False

    except MemoryError:
        print("⚠️  Пропущено: недостаточно памяти для теста")
        return True
    except Exception as e:
        print(f"✗ Ошибка: {e}")
        return False




# ============================================================================
# TEST-9: Тест Encrypt-then-MAC
# ============================================================================
def test_encrypt_then_mac():

    print_test_header("Encrypt-then-MAC")

    if not HAS_AEAD:
        print("SKIP: AEAD modules not available")
        return False


    try:
        from cryptocore.mac.hmac import HMAC
        HAS_HMAC = True
    except ImportError:
        print("SKIP: HMAC modules not available")
        return False

    test_cases = [
        (b"Test message", b"", 'ctr'),
        (b"Secret", b"AAD data", 'cbc'),
        (b"", b"Only AAD", 'cfb'),
    ]

    passed = 0
    for plaintext, aad, mode in test_cases:
        master_key = generate_random_bytes(32)

        try:
            etm = EncryptThenMAC(master_key, encryption_mode=mode)

            ciphertext, tag, iv = etm.encrypt(plaintext, aad)


            if len(tag) != 32:
                print(f"✗ Не пройден: неверный размер тега {len(tag)} байт")
                continue


            decrypted = etm.decrypt(ciphertext, tag, aad, iv)

            if decrypted == plaintext:
                print(f"✓ Пройден: {mode.upper()} режим, {len(plaintext)} байт plaintext")
                passed += 1
            else:
                print(f"✗ Не пройден: {mode.upper()} режим")


            wrong_aad = b"wrong_aad"
            try:
                decrypted_wrong = etm.decrypt(ciphertext, tag, wrong_aad, iv)
                print(f"✗ Не пройден: подмена AAD не обнаружена в режиме {mode}")
            except AEADAuthError:
                print(f"✓ Пройден: подмена AAD обнаружена в режиме {mode}")
                passed += 0.5

        except Exception as e:
            print(f"✗ Ошибка в режиме {mode}: {e}")


    normalized_passed = min(passed, len(test_cases) * 1.5)
    expected = len(test_cases) * 1.5

    print(f"\nРезультат: {normalized_passed:.1f}/{expected:.1f} баллов")
    return normalized_passed >= len(test_cases)


# ============================================================================
# CLI Тесты
# ============================================================================
def test_cli_examples():
    print_test_header("CLI примеры из требований")

    with tempfile.NamedTemporaryFile(delete=False, mode='wb', suffix='.txt') as f:
        f.write(b"Hello GCM world")
        test_input = f.name

    test_output = test_input + ".bin"
    tampered_file = test_input + ".tampered"
    should_fail_file = test_input + ".should_fail"

    key_hex = "00000000000000000000000000000000"
    nonce_hex = "000000000000000000000000"

    try:
        print("1. Тестирование: cryptocore --algorithm aes --mode gcm --encrypt...")
        encrypt_cmd = [
            sys.executable, '-m', 'cryptocore.cli', 'encrypt',
            '--mode', 'gcm',
            '--encrypt',
            '--key', f'@{key_hex}',
            '--iv', nonce_hex,
            '--aad', '',
            '--input', test_input,
            '--output', test_output,
            '--quiet'
        ]

        result = subprocess.run(encrypt_cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"✗ Ошибка шифрования: {result.stderr}")
            return False

        print("✓ Шифрование выполнено успешно")


        print("\n2. Создание подделанного файла...")


        with open(test_output, 'rb') as f_in, open(tampered_file, 'wb') as f_out:
            data = f_in.read()
            f_out.write(data)


        with open(tampered_file, 'r+b') as f:
            f.seek(50)
            f.write(b'XX')

        print("✓ Подделанный файл создан")


        print("\n3. Попытка расшифрования подделанного файла...")
        decrypt_cmd = [
            sys.executable, '-m', 'cryptocore.cli', 'encrypt',
            '--mode', 'gcm',
            '--decrypt',
            '--key', f'@{key_hex}',
            '--input', tampered_file,
            '--output', should_fail_file,
            '--aad', '',
            '--quiet'
        ]

        result = subprocess.run(decrypt_cmd, capture_output=True, text=True)


        if result.returncode == 0:
            print("✗ Не пройден: подделанный файл расшифровался успешно")
            return False

        print("✓ Подделанный файл не расшифрован (как и ожидалось)")

        if os.path.exists(should_fail_file):
            print("✗ Не пройден: выходной файл был создан несмотря на ошибку")
            return False

        print("✓ Выходной файл не создан (как и ожидалось)")


        if "authentication" in result.stderr.lower() or "аутентификации" in result.stderr.lower():
            print("✓ Сообщение об ошибке аутентификации выведено")
        else:
            print(f"⚠️  Нестандартное сообщение об ошибке: {result.stderr[:100]}...")

        return True

    except Exception as e:
        print(f"✗ Ошибка: {e}")
        return False
    finally:
        for f in [test_input, test_output, tampered_file, should_fail_file]:
            if os.path.exists(f):
                os.unlink(f)



def main():
    print("=" * 70)
    print("СПРИНТ 6: ТЕСТИРОВАНИЕ GCM И AEAD")
    print("=" * 70)

    if not HAS_AEAD:
        print("ОШИБКА: Модули AEAD не найдены")
        print("Убедитесь, что созданы:")
        print("  src/cryptocore/modes/gcm.py")
        print("  src/cryptocore/aead.py")
        return False

    mandatory_tests = [
        ("TEST-1: Тестовые векторы NIST", test_nist_test_vectors, True),
        ("TEST-2: Круговой тест", test_roundtrip, True),
        ("TEST-3: Подмена AAD", test_aad_tamper, True),
        ("TEST-4: Подмена шифртекста", test_ciphertext_tamper, True),
        ("TEST-5: Уникальность nonce", test_nonce_uniqueness, True),
        ("TEST-6: Пустой AAD", test_empty_aad, True),
        ("TEST-7: Большой AAD", test_large_aad, True),
        ("TEST-9: Encrypt-then-MAC", test_encrypt_then_mac, True),
        ("CLI Примеры", test_cli_examples, True),
    ]

    results = []
    mandatory_passed = 0
    mandatory_total = 0

    for test_name, test_func, is_mandatory in mandatory_tests:
        print(f"\nЗапуск: {test_name}")

        try:
            success = test_func()
            results.append((test_name, success, is_mandatory))

            if success:
                print(f"  ✅ {test_name}: ПРОЙДЕН")
                if is_mandatory:
                    mandatory_passed += 1
            else:
                print(f"  ❌ {test_name}: НЕ ПРОЙДЕН")

            if is_mandatory:
                mandatory_total += 1

        except Exception as e:
            print(f"  ❌ {test_name}: ОШИБКА - {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False, is_mandatory))
            if is_mandatory:
                mandatory_total += 1

    # Выводим итоговую сводку
    print("\n" + "=" * 70)
    print("ИТОГОВАЯ СВОДКА СПРИНТ 6")
    print("=" * 70)

    all_passed = 0
    all_total = 0

    for test_name, success, is_mandatory in results:
        all_total += 1
        if success:
            all_passed += 1

        status = "✅ ПРОЙДЕН" if success else "❌ НЕ ПРОЙДЕН"
        mandatory = "(обязательно)" if is_mandatory else "(желательно)"
        print(f"{status} {mandatory}: {test_name}")

    print(f"\nОбязательные тесты: {mandatory_passed}/{mandatory_total}")
    print(f"Все тесты: {all_passed}/{all_total}")

    # Проверяем успешность
    if mandatory_passed == mandatory_total:
        print("\n🎉 ВСЕ ОБЯЗАТЕЛЬНЫЕ ТЕСТЫ СПРИНТА 6 УСПЕШНО ПРОЙДЕНЫ!")
        overall_success = True
    else:
        print(f"\n⚠️  {mandatory_total - mandatory_passed} обязательных тестов не пройдено")
        overall_success = False

    return overall_success


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nТестирование прервано пользователем")
        sys.exit(130)