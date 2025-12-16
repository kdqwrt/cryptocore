try:
    from ..hash.sha256 import SHA256
    from ..hash.sha3_256 import SHA3_256

    HAS_HASH_MODULES = True
except ImportError as e:
    print(f"Warning: Hash modules not found: {e}")
    HAS_HASH_MODULES = False


    # Заглушки для тестирования
    class SHA256:
        def __init__(self):
            self.buffer = bytearray()
            self.h = [0] * 8

        def update(self, data):
            self.buffer.extend(data)

        def digest(self):
            return bytes(32)  # 32 нулевых байта


    class SHA3_256:
        def __init__(self):
            self.buffer = bytearray()

        def update(self, data):
            self.buffer.extend(data)

        def digest(self):
            return bytes(32)  # 32 нулевых байта


class HMAC:
    BLOCK_SIZES = {
        'sha256': 64,
        'sha3-256': 64,
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

        if hash_algorithm == 'sha256':
            self.hash_func = SHA256
        elif hash_algorithm == 'sha3-256':
            self.hash_func = SHA3_256

        self.key = self._process_key_rfc2104(key)

        self.ipad = 0x36
        self.opad = 0x5C

        self.key_ipad = self._xor_bytes(self.key, bytes([self.ipad] * self.block_size))
        self.key_opad = self._xor_bytes(self.key, bytes([self.opad] * self.block_size))

    def _process_key_rfc2104(self, key: bytes) -> bytes:

        key_len = len(key)


        if key_len == self.block_size:
            return key


        if key_len > self.block_size:
            hasher = self.hash_func()
            hasher.update(key)
            key = hasher.digest()


            if len(key) > self.block_size:
                hasher2 = self.hash_func()
                hasher2.update(key)
                key = hasher2.digest()

        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))

        return key

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def compute(self, message: bytes) -> bytes:

        inner_hasher = self.hash_func()
        inner_hasher.update(self.key_ipad)
        inner_hasher.update(message)
        inner_hash = inner_hasher.digest()

        outer_hasher = self.hash_func()
        outer_hasher.update(self.key_opad)
        outer_hasher.update(inner_hash)

        return outer_hasher.digest()

    def hexdigest(self, message: bytes) -> str:
        return self.compute(message).hex()


class StreamingHMAC:

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
        if self.finalized:
            raise RuntimeError("HMAC уже завершен")
        self.inner_hasher.update(data)

    def digest(self) -> bytes:
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
        return self.digest().hex()


# Тестовые векторы из RFC 4231
RFC4231_TEST_CASES = [
    # Тестовый случай 1
    {
        'key': bytes([0x0b] * 20),  # 20 байт 0x0b
        'data': b"Hi There",
        'sha256': "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    },
    # Тестовый случай 2
    {
        'key': b"Jefe",
        'data': b"what do ya want for nothing?",
        'sha256': "5bdcc146bf89754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    }
]


def verify_rfc4231() -> bool:

    print("Проверка HMAC-SHA256 на соответствие RFC 4231...")

    all_passed = True
    for i, test_case in enumerate(RFC4231_TEST_CASES, 1):
        hmac = HMAC(test_case['key'], 'sha256')
        result = hmac.hexdigest(test_case['data'])
        expected = test_case['sha256']

        if result == expected:
            print(f"✓ Тестовый случай {i} пройден")
        else:
            print(f"✗ Тестовый случай {i} не пройден")
            print(f"  Ожидалось: {expected}")
            print(f"  Получено:  {result}")
            all_passed = False

    if all_passed:
        print("✓ Все тестовые случаи RFC 4231 пройдены успешно!")
    else:
        print("✗ Некоторые тестовые случаи RFC 4231 не пройдены")

    return all_passed



def hmac_sha256(key: bytes, message: bytes) -> str:
    hmac = HMAC(key, 'sha256')
    return hmac.hexdigest(message)


def hmac_sha256_bytes(key: bytes, message: bytes) -> bytes:
    hmac = HMAC(key, 'sha256')
    return hmac.compute(message)


def hmac_sha3_256(key: bytes, message: bytes) -> str:
    hmac = HMAC(key, 'sha3-256')
    return hmac.hexdigest(message)


def hmac_sha3_256_bytes(key: bytes, message: bytes) -> bytes:
    hmac = HMAC(key, 'sha3-256')
    return hmac.compute(message)


if __name__ == '__main__':
    verify_rfc4231()