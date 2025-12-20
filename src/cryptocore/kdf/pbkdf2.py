"""
Реализация PBKDF2-HMAC-SHA256 согласно RFC 2898.
Использует HMAC-SHA256 из предыдущего спринта.
"""
from cryptocore.mac.hmac import HMAC


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """
    HMAC-SHA256 с использованием нашей реализации из Спринта 5.

    Args:
        key: Ключ HMAC
        msg: Сообщение для хеширования

    Returns:
        HMAC-SHA256 хеш
    """
    hmac = HMAC(key, 'sha256')
    return hmac.compute(msg)


def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """
    Реализация PBKDF2-HMAC-SHA256 согласно RFC 2898.

    DK = T1 ∥ T2 ∥ ... ∥ Tdklen, где Ti = F(P, S, c, i)
    F(P, S, c, i) = U1 ⊕ U2 ⊕ ... ⊕ Uc
    U1 = PRF(P, S ∥ INT_32_BE(i))
    Uj = PRF(P, Uj-1)

    Args:
        password: Пароль в виде байтов
        salt: Соль в виде байтов
        iterations: Количество итераций (c)
        dklen: Желаемая длина ключа в байтах

    Returns:
        Полученный ключ заданной длины

    Raises:
        ValueError: Если dklen или iterations неположительные
    """
    if dklen <= 0:
        raise ValueError("dklen должен быть положительным числом")

    if iterations <= 0:
        raise ValueError("iterations должен быть положительным числом")

    # Размер выхода HMAC-SHA256 (32 байта)
    hlen = 32

    # Количество блоков
    blocks_needed = (dklen + hlen - 1) // hlen  # ceil(dklen / hlen)
    derived_key = bytearray()

    # Вычисляем каждый блок Ti
    for i in range(1, blocks_needed + 1):
        # U1 = HMAC-SHA256(password, salt || INT_32_BE(i))
        current_block_input = salt + i.to_bytes(4, 'big')
        u_current = hmac_sha256(password, current_block_input)

        # Инициализируем блок аккумулятора с U1
        accumulator = bytearray(u_current)

        # Вычисляем U2 через Uc и XOR с аккумулятором
        for _ in range(2, iterations + 1):
            # Uj = HMAC(password, Uj-1)
            u_current = hmac_sha256(password, u_current)

            # XOR: accumulator = accumulator ⊕ u_current
            for j in range(hlen):
                accumulator[j] ^= u_current[j]

        derived_key.extend(accumulator)

    # Вернуть ровно dklen байт
    return bytes(derived_key[:dklen])


def pbkdf2(password: str, salt_hex: str, iterations: int = 100000, dklen: int = 32) -> str:
    """
    Удобная функция для работы со строками.

    Args:
        password: Строка пароля
        salt_hex: Соль в шестнадцатеричном формате или строка
        iterations: Количество итераций (по умолчанию 100000)
        dklen: Длина ключа в байтах (по умолчанию 32)

    Returns:
        Полученный ключ в шестнадцатеричном формате
    """
    # Конвертируем пароль в байты
    if isinstance(password, str):
        password_bytes = password.encode('utf-8')
    else:
        password_bytes = password

    # Конвертируем соль из hex в байты
    if isinstance(salt_hex, str):
        if all(c in '0123456789abcdefABCDEF' for c in salt_hex):
            salt_bytes = bytes.fromhex(salt_hex)
        else:
            # Если не hex, считаем это строкой
            salt_bytes = salt_hex.encode('utf-8')
    else:
        salt_bytes = salt_hex

    key_bytes = pbkdf2_hmac_sha256(password_bytes, salt_bytes, iterations, dklen)
    return key_bytes.hex()