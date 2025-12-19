import os
from typing import Generator, Tuple, Optional


def read_file(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        return f.read()


def read_file_chunks(filename: str, chunk_size: int = 8192) -> Generator[bytes, None, None]:

    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def write_file(filename: str, data: bytes):
    """Запись данных в файл."""
    directory = os.path.dirname(filename)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(filename, 'wb') as f:
        f.write(data)


def read_file_with_iv(filename: str) -> Tuple[bytes, bytes]:

    data = read_file(filename)

    if len(data) < 16:
        raise ValueError("File is too short to contain IV (less than 16 bytes)")

    iv = data[:16]
    actual_data = data[16:]
    return iv, actual_data


def write_file_with_iv(filename: str, iv: bytes, data: bytes):
    """Запись файла с IV в начале."""
    write_file(filename, iv + data)



def read_file_with_nonce(filename: str, nonce_size: int = 12) -> Tuple[bytes, bytes]:

    data = read_file(filename)

    if len(data) < nonce_size:
        raise ValueError(f"File is too short to contain nonce (less than {nonce_size} bytes)")

    nonce = data[:nonce_size]
    rest_data = data[nonce_size:]
    return nonce, rest_data


def write_file_with_nonce(filename: str, nonce: bytes, data: bytes):
    """Запись файла с nonce в начале."""
    write_file(filename, nonce + data)


def read_gcm_file(filename: str) -> Tuple[bytes, bytes, bytes]:

    data = read_file(filename)

    if len(data) < 28:  # 12 байт nonce + 16 байт тег
        raise ValueError("File is too short for GCM format (less than 28 bytes)")

    nonce = data[:12]
    ciphertext_with_tag = data[12:]

    # Разделяем ciphertext и tag
    if len(ciphertext_with_tag) < 16:
        raise ValueError("Data too short to contain tag (less than 16 bytes)")

    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return nonce, ciphertext, tag


def write_gcm_file(filename: str, nonce: bytes, ciphertext: bytes, tag: bytes):

    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for GCM")
    if len(tag) != 16:
        raise ValueError("Tag must be 16 bytes for GCM")

    write_file(filename, nonce + ciphertext + tag)


def read_etm_file(filename: str, iv_size: int = 16, tag_size: int = 32) -> Tuple[bytes, bytes, bytes]:

    data = read_file(filename)

    min_size = iv_size + tag_size
    if len(data) < min_size:
        raise ValueError(f"File is too short for ETM format (less than {min_size} bytes)")

    iv = data[:iv_size]
    ciphertext_with_tag = data[iv_size:]

    # Разделяем ciphertext и tag
    if len(ciphertext_with_tag) < tag_size:
        raise ValueError(f"Data too short to contain tag (less than {tag_size} bytes)")

    ciphertext = ciphertext_with_tag[:-tag_size]
    tag = ciphertext_with_tag[-tag_size:]

    return iv, ciphertext, tag


def write_etm_file(filename: str, iv: bytes, ciphertext: bytes, tag: bytes):
    """
    Запись файла в формате Encrypt-then-MAC.
    Формат: [IV][шифртекст][тег]
    """
    write_file(filename, iv + ciphertext + tag)


def safe_write_file(filename: str, data: bytes, temp_suffix: str = ".tmp") -> bool:

    temp_file = filename + temp_suffix
    success = False

    try:
        # Записываем во временный файл
        write_file(temp_file, data)

        # Атомарная замена (если поддерживается ОС)
        if os.name == 'nt':  # Windows
            if os.path.exists(filename):
                os.remove(filename)
            os.rename(temp_file, filename)
        else:  # Unix-like
            os.replace(temp_file, filename)

        success = True

    except Exception as e:
        # В случае ошибки пытаемся удалить временный файл
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except:
            pass
        raise e

    return success


def delete_file_if_exists(filename: str):
    """Удаление файла, если он существует."""
    try:
        if os.path.exists(filename):
            os.remove(filename)
    except Exception as e:
        print(f"Warning: Could not delete file {filename}: {e}")


def read_file_with_format(filename: str, format_type: str = "gcm") -> Tuple:

    if format_type == "gcm":
        return read_gcm_file(filename)
    elif format_type == "etm":
        return read_etm_file(filename)
    elif format_type == "iv":
        return read_file_with_iv(filename)
    elif format_type == "nonce":
        return read_file_with_nonce(filename)
    elif format_type == "raw":
        return (read_file(filename),)
    else:
        raise ValueError(f"Unsupported format: {format_type}")


def write_file_with_format(filename: str, format_type: str = "gcm", **kwargs):
    """
    Универсальная функция записи файлов разных форматов.

    Args:
        filename: Имя файла
        format_type: Тип формата ("gcm", "etm", "iv", "nonce", "raw")
        **kwargs: Параметры, зависящие от формата
    """
    if format_type == "gcm":
        write_gcm_file(filename, kwargs['nonce'], kwargs['ciphertext'], kwargs['tag'])
    elif format_type == "etm":
        write_etm_file(filename, kwargs['iv'], kwargs['ciphertext'], kwargs['tag'])
    elif format_type == "iv":
        write_file_with_iv(filename, kwargs['iv'], kwargs['data'])
    elif format_type == "nonce":
        write_file_with_nonce(filename, kwargs['nonce'], kwargs['data'])
    elif format_type == "raw":
        write_file(filename, kwargs['data'])
    else:
        raise ValueError(f"Unsupported format: {format_type}")




def get_file_size(filename: str) -> int:
    return os.path.getsize(filename)


def file_exists(filename: str) -> bool:
    return os.path.exists(filename) and os.path.isfile(filename)


def is_file_readable(filename: str) -> bool:
    return os.access(filename, os.R_OK)


def is_file_writable(filename: str) -> bool:
    if os.path.exists(filename):
        return os.access(filename, os.W_OK)
    else:
        # Проверяем доступность директории для записи
        directory = os.path.dirname(filename) or '.'
        return os.access(directory, os.W_OK)


def verify_file_integrity_after_write(filename: str, expected_size: Optional[int] = None) -> bool:

    try:
        if not file_exists(filename):
            return False

        if expected_size is not None:
            actual_size = get_file_size(filename)
            if actual_size != expected_size:
                print(f"Warning: File size mismatch. Expected {expected_size}, got {actual_size}")
                return False

        # Попытка чтения небольшой части файла
        with open(filename, 'rb') as f:
            f.read(1)  # Читаем один байт для проверки доступности

        return True

    except Exception as e:
        print(f"Warning: File integrity check failed: {e}")
        return False