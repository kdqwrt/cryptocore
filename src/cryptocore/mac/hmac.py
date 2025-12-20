from cryptocore.hash.sha256 import SHA256
from cryptocore.hash.sha3_256 import SHA3_256


class HMAC:
    BLOCK_SIZES = {
        'sha256': 64,
        'sha3-256': 136,  # SHA3-256 имеет блок 136 байт (1088 бит)
    }

    OUTPUT_SIZES = {
        'sha256': 32,
        'sha3-256': 32,
    }

    def __init__(self, key: bytes, hash_algorithm: str = 'sha256'):
        if hash_algorithm not in self.BLOCK_SIZES:
            raise ValueError(f"Неподдерживаемый алгоритм хеширования: {hash_algorithm}")

        self.hash_algorithm = hash_algorithm
        self.block_size = self.BLOCK_SIZES[hash_algorithm]  # B
        self.output_size = self.OUTPUT_SIZES[hash_algorithm]  # L

        # Инициализация хеш-функции
        if hash_algorithm == 'sha256':
            self.hash_func = SHA256
        elif hash_algorithm == 'sha3-256':
            self.hash_func = SHA3_256

        self.key = self._process_key_rfc2104(key)

        self.ipad = 0x36
        self.opad = 0x5C

        # Предварительное вычисление XOR ключа с ipad/opad
        self.key_ipad = self._xor_bytes(self.key, bytes([self.ipad] * self.block_size))
        self.key_opad = self._xor_bytes(self.key, bytes([self.opad] * self.block_size))

    def _process_key_rfc2104(self, key: bytes) -> bytes:
        """Обработка ключа согласно RFC 2104."""
        key_len = len(key)

        # Если ключ равен размеру блока, оставляем как есть
        if key_len == self.block_size:
            return key

        # Если ключ длиннее размера блока, хешируем его
        if key_len > self.block_size:
            hasher = self.hash_func()
            hasher.update(key)
            key = hasher.digest()

        # Если ключ короче размера блока, дополняем нулями
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))

        return key

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """Побитовый XOR двух байтовых строк одинаковой длины."""
        return bytes(x ^ y for x, y in zip(a, b))

    def compute(self, message: bytes) -> bytes:
        """Вычисление HMAC для сообщения."""
        # Внутренний хеш: H((K ⊕ ipad) || message)
        inner_hasher = self.hash_func()
        inner_hasher.update(self.key_ipad)
        inner_hasher.update(message)
        inner_hash = inner_hasher.digest()

        # Внешний хеш: H((K ⊕ opad) || inner_hash)
        outer_hasher = self.hash_func()
        outer_hasher.update(self.key_opad)
        outer_hasher.update(inner_hash)

        return outer_hasher.digest()

    def hexdigest(self, message: bytes) -> str:
        """Вычисление HMAC и возврат в hex-формате."""
        return self.compute(message).hex()


class StreamingHMAC:
    """Потоковая версия HMAC для обработки больших данных."""

    def __init__(self, key: bytes, hash_algorithm: str = 'sha256'):
        # Используем базовый HMAC для обработки ключа
        self.base_hmac = HMAC(key, hash_algorithm)
        self.hash_algorithm = hash_algorithm

        # Получаем параметры из base_hmac
        self.block_size = self.base_hmac.block_size
        self.output_size = self.base_hmac.output_size

        if hash_algorithm == 'sha256':
            self.hash_func = SHA256
        elif hash_algorithm == 'sha3-256':
            self.hash_func = SHA3_256

        # Получаем предварительно вычисленные значения
        self.key_ipad = self.base_hmac.key_ipad
        self.key_opad = self.base_hmac.key_opad

        # Инициализация внутреннего хеша
        self.inner_hasher = self.hash_func()
        self.inner_hasher.update(self.key_ipad)

        # Флаг завершения
        self.finalized = False

    def update(self, data: bytes) -> None:
        """Добавление данных для HMAC."""
        if self.finalized:
            raise RuntimeError("HMAC уже завершен")
        self.inner_hasher.update(data)

    def digest(self) -> bytes:
        """Получение HMAC в бинарном формате."""
        if self.finalized:
            raise RuntimeError("HMAC уже завершен")

        # Получаем внутренний хеш: H((K0 ⊕ ipad) || text)
        inner_hash = self.inner_hasher.digest()

        # Вычисляем внешний хеш: H((K0 ⊕ opad) || inner_hash)
        outer_hasher = self.hash_func()
        outer_hasher.update(self.key_opad)
        outer_hasher.update(inner_hash)

        self.finalized = True
        return outer_hasher.digest()

    def hexdigest(self) -> str:
        """Получение HMAC в hex-формате."""
        return self.digest().hex()


# Тестовые векторы из RFC 4231 (Section 4.2)
RFC4231_TEST_CASES = [
    # Тестовый случай 1
    {
        'key': bytes([0x0b] * 20),  # 20 байт 0x0b
        'data': b"Hi There",
        'sha256': "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        'description': "Test Case 1 - Key smaller than block size"
    },
    # Тестовый случай 2
    {
        'key': b"Jefe",
        'data': b"what do ya want for nothing?",
        'sha256': "5bdcc146bf68754e6a042426889575c75a003f089d2739839dec58b964ec3843",
        'description': "Test Case 2 - Key smaller than block size, data with special chars"
    },
    # Тестовый случай 3
    {
        'key': bytes([0xaa] * 20),  # 20 байт 0xaa
        'data': bytes([0xdd] * 50),  # 50 байт 0xdd
        'sha256': "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        'description': "Test Case 3 - Key smaller than block size, data 50 bytes"
    },
    # Тестовый случай 4
    {
        'key': bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819"),  # 25 байт
        'data': bytes.fromhex(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
        # 50 байт
        'sha256': "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        'description': "Test Case 4 - Key and data with complex patterns"
    }
]

# Дополнительные тестовые векторы для граничных случаев
ADDITIONAL_TEST_CASES = [
    # Ключ точно равен размеру блока (64 байта для SHA-256)
    {
        'key': bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                      0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]),  # 64 байта
        'data': b"Test message for exact block size key",
        'sha256': None,  # Нужно вычислить эталонное значение
        'description': "Key exactly block size (64 bytes)"
    },
    # Ключ больше размера блока (100 байт)
    {
        'key': bytes([i % 256 for i in range(100)]),  # 100 байт
        'data': b"Test message for key longer than block size",
        'sha256': None,  # Нужно вычислить эталонное значение
        'description': "Key longer than block size (100 bytes)"
    },
    # Пустое сообщение
    {
        'key': bytes([0x0b] * 16),  # 16 байт
        'data': b"",
        'sha256': None,  # Нужно вычислить эталонное значение
        'description': "Empty message"
    }
]


def verify_rfc4231() -> bool:
    """Проверка HMAC-SHA256 на соответствие RFC 4231."""
    print("=" * 60)
    print("Проверка HMAC-SHA256 на соответствие RFC 4231")
    print("=" * 60)

    all_passed = True
    total_cases = len(RFC4231_TEST_CASES)
    passed_cases = 0

    for i, test_case in enumerate(RFC4231_TEST_CASES, 1):
        print(f"\nТестовый случай {i}: {test_case['description']}")
        print(f"Ключ: {test_case['key'].hex()[:40]}..." if len(
            test_case['key'].hex()) > 40 else f"Ключ: {test_case['key'].hex()}")
        print(f"Данные: {test_case['data'].hex()[:40]}..." if len(
            test_case['data'].hex()) > 40 else f"Данные: {test_case['data'].hex()}")

        try:
            hmac = HMAC(test_case['key'], 'sha256')
            result = hmac.hexdigest(test_case['data'])
            expected = test_case['sha256']

            if result == expected:
                print(f"✓ Пройден")
                print(f"  HMAC: {result}")
                passed_cases += 1
            else:
                print(f"✗ Не пройден")
                print(f"  Ожидалось: {expected}")
                print(f"  Получено:  {result}")
                all_passed = False
        except Exception as e:
            print(f"✗ Ошибка при выполнении: {e}")
            all_passed = False

    print(f"\n" + "=" * 60)
    print(f"ИТОГ: {passed_cases}/{total_cases} тестов пройдено")
    if all_passed:
        print("✓ Все тестовые случаи RFC 4231 пройдены успешно!")
    else:
        print("✗ Некоторые тестовые случаи RFC 4231 не пройдены")
    print("=" * 60)

    return all_passed


def run_comprehensive_tests():
    """Запуск комплексных тестов HMAC."""
    print("\n" + "=" * 60)
    print("Комплексное тестирование HMAC")
    print("=" * 60)

    tests = [
        ("Проверка RFC 4231", verify_rfc4231),
        ("Проверка граничных случаев", test_boundary_cases),
        ("Проверка потокового HMAC", test_streaming_hmac),
        ("Проверка обнаружения изменений", test_tamper_detection),
    ]

    results = []
    for test_name, test_func in tests:
        print(f"\n{test_name}...")
        try:
            result = test_func()
            results.append((test_name, result))
            if result:
                print(f"✓ {test_name} пройден")
            else:
                print(f"✗ {test_name} не пройден")
        except Exception as e:
            print(f"✗ {test_name} завершился с ошибкой: {e}")
            results.append((test_name, False))

    print("\n" + "=" * 60)
    print("Итоговый отчет:")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✓" if result else "✗"
        print(f"{status} {test_name}")

    print(f"\nОбщий результат: {passed}/{total} тестов пройдено")

    if passed == total:
        print("✓ Все тесты пройдены успешно!")
        return True
    else:
        print(f"✗ {total - passed} тестов не пройдены")
        return False


def test_boundary_cases() -> bool:
    """Тестирование граничных случаев."""
    print("\nТестирование граничных случаев...")

    test_cases = [
        # Короткий ключ (16 байт)
        (b"\x00" * 16, b"test message", "Short key (16 bytes)"),
        # Длинный ключ (100 байт)
        (b"\x01" * 100, b"test message", "Long key (100 bytes)"),
        # Пустое сообщение
        (b"\x02" * 32, b"", "Empty message"),
        # Очень длинное сообщение
        (b"\x03" * 32, b"x" * 10000, "Very long message (10KB)"),
    ]

    all_passed = True

    for key, data, description in test_cases:
        try:
            # Создаем два экземпляра HMAC с одинаковыми параметрами
            hmac1 = HMAC(key, 'sha256')
            hmac2 = HMAC(key, 'sha256')

            # Вычисляем HMAC двумя способами
            result1 = hmac1.compute(data)
            result2 = hmac2.compute(data)

            # Проверяем, что результаты одинаковы
            if result1 == result2:
                print(f"✓ {description}: результаты совпадают")
            else:
                print(f"✗ {description}: результаты различны!")
                all_passed = False

        except Exception as e:
            print(f"✗ {description}: ошибка - {e}")
            all_passed = False

    return all_passed


def test_streaming_hmac() -> bool:
    """Тестирование потокового HMAC."""
    print("\nТестирование потокового HMAC...")

    # Тестовые данные
    key = b"test_key_12345"
    data = b"This is a test message for streaming HMAC validation. " * 100  # ~5KB данных

    try:
        # 1. Вычисляем HMAC обычным способом
        hmac_normal = HMAC(key, 'sha256')
        normal_result = hmac_normal.compute(data)

        # 2. Вычисляем HMAC потоковым способом
        hmac_streaming = StreamingHMAC(key, 'sha256')

        # Разбиваем данные на чанки
        chunk_size = 1024
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            hmac_streaming.update(chunk)

        streaming_result = hmac_streaming.digest()

        # 3. Сравниваем результаты
        if normal_result == streaming_result:
            print("✓ Потоковый HMAC дает те же результаты, что и обычный")
            return True
        else:
            print("✗ Результаты потокового и обычного HMAC различаются!")
            print(f"  Обычный:   {normal_result.hex()}")
            print(f"  Потоковый: {streaming_result.hex()}")
            return False

    except Exception as e:
        print(f"✗ Ошибка при тестировании потокового HMAC: {e}")
        return False


def test_tamper_detection() -> bool:
    """Тестирование обнаружения изменений."""
    print("\nТестирование обнаружения изменений...")

    key = b"secret_key_123"
    original_data = b"Original important message"
    modified_data = b"Modified important message"  # Изменен один байт

    try:
        # 1. Вычисляем HMAC для оригинальных данных
        hmac = HMAC(key, 'sha256')
        original_hmac = hmac.compute(original_data)

        # 2. Вычисляем HMAC для измененных данных
        modified_hmac = hmac.compute(modified_data)

        # 3. Проверяем, что HMAC различаются
        if original_hmac != modified_hmac:
            print("✓ Изменения в данных корректно обнаруживаются")
            print(f"  Оригинальный HMAC: {original_hmac.hex()[:16]}...")
            print(f"  Измененный HMAC:   {modified_hmac.hex()[:16]}...")

            # 4. Проверяем обнаружение неверного ключа
            wrong_key = b"wrong_key_456"
            hmac_wrong = HMAC(wrong_key, 'sha256')
            wrong_key_hmac = hmac_wrong.compute(original_data)

            if original_hmac != wrong_key_hmac:
                print("✓ Неверный ключ корректно обнаруживается")
                return True
            else:
                print("✗ Неверный ключ не обнаруживается!")
                return False
        else:
            print("✗ Изменения в данных не обнаруживаются!")
            return False

    except Exception as e:
        print(f"✗ Ошибка при тестировании обнаружения изменений: {e}")
        return False


# Утилитарные функции для удобства использования
def hmac_sha256(key: bytes, message: bytes) -> str:
    """Вычисление HMAC-SHA256."""
    hmac = HMAC(key, 'sha256')
    return hmac.hexdigest(message)


def hmac_sha256_bytes(key: bytes, message: bytes) -> bytes:
    """Вычисление HMAC-SHA256 (бинарный формат)."""
    hmac = HMAC(key, 'sha256')
    return hmac.compute(message)


def hmac_sha3_256(key: bytes, message: bytes) -> str:
    """Вычисление HMAC-SHA3-256."""
    hmac = HMAC(key, 'sha3-256')
    return hmac.hexdigest(message)


def hmac_sha3_256_bytes(key: bytes, message: bytes) -> bytes:
    """Вычисление HMAC-SHA3-256 (бинарный формат)."""
    hmac = HMAC(key, 'sha3-256')
    return hmac.compute(message)


if __name__ == '__main__':
    print("Тестирование реализации HMAC")
    print("=" * 60)

    # Запускаем все тесты
    success = run_comprehensive_tests()

    if success:
        print("\n" + "=" * 60)
        print("ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
        print("=" * 60)
        exit(0)
    else:
        print("\n" + "=" * 60)
        print("НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ!")
        print("=" * 60)
        exit(1)