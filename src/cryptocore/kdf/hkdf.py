"""
Упрощенная реализация иерархии ключей на основе HMAC.
HMAC(master_key, context || counter)
"""
from cryptocore.mac.hmac import HMAC


def derive_key(master_key: bytes, context: str, length: int = 32) -> bytes:
    """
    Получить ключ из мастер-ключа, используя детерминированный метод на основе HMAC.

    T_i = HMAC(master_key, context || counter)
    derived_key = T1 ∥ T2 ∥ ... (усекается до нужной длины)

    Args:
        master_key: Мастер-ключ в виде байтов
        context: Строка контекста (например, "шифрование", "аутентификация")
        length: Желаемая длина ключа в байтах (по умолчанию 32)

    Returns:
        Полученный ключ заданной длины

    Raises:
        ValueError: Если length неположительное
    """
    if length <= 0:
        raise ValueError("length должен быть положительным числом")

    # Конвертируем контекст в байты если необходимо
    if isinstance(context, str):
        context_bytes = context.encode('utf-8')
    else:
        context_bytes = context

    derived = bytearray()
    counter = 1

    # Генерируем достаточно байт
    while len(derived) < length:
        # T_i = HMAC(master_key, context || INT_32_BE(counter))
        block_input = context_bytes + counter.to_bytes(4, 'big')

        # Используем нашу реализацию HMAC-SHA256
        hmac = HMAC(master_key, 'sha256')
        block = hmac.compute(block_input)

        derived.extend(block)
        counter += 1

    # Усекаем до нужной длины
    return bytes(derived[:length])


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