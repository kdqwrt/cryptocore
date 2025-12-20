
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def test_salt_randomness():
    print("=" * 60)
    print("Тестирование случайности генерации соли")
    print("=" * 60)

    # Используем функцию из CLI для генерации соли
    from cryptocore.csprng import generate_random_bytes

    salts = set()
    collisions = 0

    print("Генерация 1000 случайных солей...")

    for i in range(1000):
        salt = generate_random_bytes(16)
        salt_hex = salt.hex()

        if salt_hex in salts:
            collisions += 1
            print(f"Обнаружено столкновение на итерации {i}")

        salts.add(salt_hex)

        # Прогресс
        if (i + 1) % 100 == 0:
            print(f"  Сгенерировано {i + 1}/1000 солей...")

    print("-" * 60)
    print(f"Всего сгенерировано солей: {len(salts)}")
    print(f"Столкновений: {collisions}")

    if collisions == 0:
        print(" Нет столкновений - соли уникальны")
    else:
        print(f" Найдено {collisions} столкновений")

    # Проверка энтропии
    print("\nАнализ энтропии (первые 100 солей):")
    byte_counts = [[0] * 256 for _ in range(16)]

    for i, salt_hex in enumerate(list(salts)[:100]):
        salt = bytes.fromhex(salt_hex)
        for j in range(16):
            byte_counts[j][salt[j]] += 1

    # Проверяем распределение байтов
    uniform_distribution = True
    for pos in range(16):
        non_zero_bytes = sum(1 for count in byte_counts[pos] if count > 0)
        if non_zero_bytes < 200:  # Менее 200 разных значений из 256
            print(f"  Позиция {pos}: только {non_zero_bytes}/256 разных значений")
            uniform_distribution = False

    if uniform_distribution:
        print(" Распределение байтов выглядит равномерным")
    else:
        print(" Распределение байтов может быть неравномерным")

    return collisions == 0


def test_salt_lengths():
    print("\n" + "=" * 60)
    print("Тестирование различных длин соли")
    print("=" * 60)

    from cryptocore.csprng import generate_random_bytes

    test_lengths = [8, 16, 24, 32, 64]

    for length in test_lengths:
        salt = generate_random_bytes(length)
        print(f"  Длина {length:2d} байт: {salt.hex()[:32]}...")

    print("✓ Поддерживаются различные длины соли")
    return True


def main():
    print("Запуск тестов случайности соли")
    print()

    all_passed = True

    if not test_salt_randomness():
        all_passed = False

    if not test_salt_lengths():
        all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print(" ВСЕ ТЕСТЫ СОЛИ ПРОЙДЕНЫ УСПЕШНО!")
    else:
        print(" НЕКОТОРЫЕ ТЕСТЫ СОЛИ НЕ ПРОЙДЕНЫ")
    print("=" * 60)

    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())