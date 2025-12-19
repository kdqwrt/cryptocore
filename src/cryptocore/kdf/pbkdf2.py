"""
Реализация PBKDF2-HMAC-SHA256 согласно RFC 2898.
Использует HMAC-SHA256 из предыдущего спринта.
"""
from cryptocore.mac.hmac import HMAC


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

    # Количество блоков HMAC-SHA256 (32 байта на блок)
    blocks_needed = (dklen + 31) // 32  # ceil(dklen / 32)
    derived_key = bytearray()

    # Вычисляем каждый блок Ti
    for block_index in range(1, blocks_needed + 1):
        # U1 = HMAC-SHA256(password, salt || INT_32_BE(i))
        hmac_input = salt + block_index.to_bytes(4, 'big')
        hmac = HMAC(password, 'sha256')
        u_prev = hmac.compute(hmac_input)

        # Начинаем с U1
        block = bytearray(u_prev)

        # Вычисляем U2 через Uc и XOR с блоком
        for _ in range(2, iterations + 1):
            hmac = HMAC(password, 'sha256')
            u_curr = hmac.compute(u_prev)

            # XOR: block = block ⊕ u_curr
            for k in range(len(block)):
                block[k] ^= u_curr[k]

            u_prev = u_curr

        derived_key.extend(block)

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