import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cryptocore.kdf.hkdf import derive_key


def test_hkdf_functionality():
    print("=" * 60)
    print("Тестирование HKDF (иерархии ключей)")
    print("=" * 60)

    tests_passed = 0
    total_tests = 6

    master_key = b'\x00' * 32  # 32 нулевых байта

    # Тест 1: Детерминированность
    try:
        key1 = derive_key(master_key, "encryption", 32)
        key2 = derive_key(master_key, "encryption", 32)
        assert key1 == key2, "HKDF не детерминирован"
        print("✓ Тест 1: HKDF детерминирован")
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ Тест 1: {e}")

    # Тест 2: Разные длины ключей
    try:
        lengths = [1, 16, 32, 64, 128, 256]
        for length in lengths:
            key = derive_key(master_key, "test", length)
            assert len(key) == length, f"Неверная длина: {len(key)} вместо {length}"
        print("✓ Тест 2: Поддерживаются разные длины ключей")
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ Тест 2: {e}")

    # Тест 3: Разные контексты дают разные ключи (контекстное разделение)
    try:
        key1 = derive_key(master_key, "encryption", 32)
        key2 = derive_key(master_key, "authentication", 32)
        key3 = derive_key(master_key, "key_encryption", 32)

        # Все ключи должны быть разными
        assert key1 != key2, "Ключи для разных контекстов не должны совпадать"
        assert key1 != key3, "Ключи для разных контекстов не должны совпадать"
        assert key2 != key3, "Ключи для разных контекстов не должны совпадать"

        print("✓ Тест 3: Разные контексты дают разные ключи")
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ Тест 3: {e}")

    # Тест 4: Разные мастер-ключи дают разные ключи
    try:
        master1 = b'\x01' * 32
        master2 = b'\x02' * 32

        key1 = derive_key(master1, "same_context", 32)
        key2 = derive_key(master2, "same_context", 32)

        assert key1 != key2, "Разные мастер-ключи должны давать разные ключи"
        print("✓ Тест 4: Разные мастер-ключи дают разные ключи")
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ Тест 4: {e}")

    # Тест 5: Большие длины (требующие нескольких блоков HMAC)
    try:

        long_key = derive_key(master_key, "large_key", 500)
        assert len(long_key) == 500, f"Неверная длина длинного ключа: {len(long_key)}"


        first_part = long_key[:100]
        second_part = long_key[100:200]
        assert first_part != second_part, "Длинный ключ не выглядит случайным"

        print("✓ Тест 5: Поддерживаются большие длины ключей (500+ байт)")
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ Тест 5: {e}")

    # Тест 6: Unicode контексты
    try:
        key1 = derive_key(master_key, "шифрование", 32)
        key2 = derive_key(master_key, "зашифровать", 32)

        assert key1 != key2, "Unicode контексты должны давать разные ключи"
        print("✓ Тест 6: Поддерживаются Unicode контексты")
        tests_passed += 1
    except AssertionError as e:
        print(f"✗ Тест 6: {e}")

    print("-" * 60)
    print(f"Результат: {tests_passed}/{total_tests} тестов пройдено")

    if tests_passed == total_tests:
        print(" ВСЕ ТЕСТЫ HKDF ПРОЙДЕНЫ")
        return True
    else:
        print(" НЕКОТОРЫЕ ТЕСТЫ HKDF НЕ ПРОЙДЕНЫ")
        return False


def test_hkdf_security():

    print("\n" + "=" * 60)
    print("Тестирование безопасности HKDF")
    print("=" * 60)

    master_key = b'\x00' * 32

    # Проверяем, что небольшие изменения в контексте дают совершенно разные ключи
    print("Проверка лавинного эффекта для контекстов...")

    contexts = [
        "context",
        "context1",
        "contexta",
        "contex",
        "Context",
    ]

    keys = {}
    for ctx in contexts:
        key = derive_key(master_key, ctx, 32)
        keys[ctx] = key.hex()

    # Сравниваем все пары ключей
    different_pairs = 0
    total_pairs = 0

    for i, ctx1 in enumerate(contexts):
        for ctx2 in contexts[i + 1:]:
            total_pairs += 1
            if keys[ctx1] != keys[ctx2]:
                different_pairs += 1
            else:
                print(f" Предупреждение: одинаковые ключи для '{ctx1}' и '{ctx2}'")

    print(f"Из {total_pairs} пар контекстов, {different_pairs} дали разные ключи")

    if different_pairs == total_pairs:
        print("✓ Лавинный эффект работает: любые изменения контекста меняют ключ")
        return True
    else:
        print(" Не все изменения контекста дают разные ключи")
        return False


def main():
    """Запуск всех тестов HKDF."""
    print(" Запуск тестов HKDF ")
    print()

    all_passed = True

    if not test_hkdf_functionality():
        all_passed = False

    if not test_hkdf_security():
        all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("ВСЕ ТЕСТЫ HKDF ПРОЙДЕНЫ УСПЕШНО!")
    else:
        print("НЕКОТОРЫЕ ТЕСТЫ HKDF НЕ ПРОЙДЕНЫ")
    print("=" * 60)

    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())