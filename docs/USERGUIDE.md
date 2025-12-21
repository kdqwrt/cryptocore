# Руководство пользователя CryptoCore

## Установка

```bash
https://github.com/kdqwrt/cryptocore.git
python3 -m venv venv
source venv/bin/activate
pip install -e .
cryptocore --help
```
## Быстрая шпаргалка
```bash
echo "Тестовые данные" > test.txt

cryptocore encrypt --mode gcm --encrypt --input test.txt --output test.enc
cryptocore encrypt --mode gcm --decrypt --key @ВАШ_КЛЮЧ --input test.enc --output test_decrypted.txt
cat test_decrypted.txt
```
## Основные команды
Шифрование GCM 
```bash
cryptocore encrypt --mode gcm --encrypt --key @00112233445566778899aabbccddeeff --input файл.txt --output файл.enc
cryptocore encrypt --mode gcm --decrypt --key @00112233445566778899aabbccddeeff --input файл.enc --output файл.txt
```
Шифрование GCM с AAD
```bash
cryptocore encrypt --mode gcm --encrypt --key @ключ --input данные.txt --output данные.enc --aad 0102030405
cryptocore encrypt --mode gcm --decrypt --key @ключ --input данные.enc --output данные.txt --aad 0102030405
```
Другие режимы шифрования
```bash
cryptocore encrypt --mode cbc --encrypt --key @ключ --input файл.txt --output файл.enc
cryptocore encrypt --mode ctr --encrypt --key @ключ --input файл.txt --output файл.enc
cryptocore encrypt --mode ecb --encrypt --key @ключ --input файл.txt --output файл.enc
```
Хеширование файлов
```bash
cryptocore dgst --algorithm sha256 --input файл.iso
cryptocore dgst --algorithm sha3-256 --input файл.iso
cryptocore dgst --algorithm sha256 --input файл1.txt файл2.txt файл3.txt
```
HMAC подписи
```bash
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input файл.txt
cryptocore dgst --algorithm sha256 --hmac --key ключ --input файл.txt --verify файл.hmac
```
Работа с ключами
```bash
python3 -c "import os; print('@' + os.urandom(16).hex())"
cryptocore derive --password "мойпароль" --length 32
cryptocore derive --password "пароль" --salt a1b2c3d4e5f6 --iterations 100000 --length 16
```
## Устранение неполадок

### Ошибки при шифровании

**Ошибка: "ValueError: Key must be 16 bytes for AES-128"**
Причина: Ключ неверной длины.
Решение:

Используйте ключ ровно 16 байт (32 hex символа)

Сгенерируйте новый ключ: 
```bash
python3 -c "import os; print('@' + os.urandom(16).hex())"
```
Используйте PBKDF2 для получения ключа из пароля:
```bash
cryptocore derive --password "пароль" --length 16
```

**Ошибка: "AuthenticationError: MAC verification failed"**
Причина: Неверный ключ, поврежденные данные или неверный AAD.
Решение:

1.Проверьте правильность ключа

2.Проверьте целостность зашифрованного файла

3.Убедитесь, что используете тот же AAD, что и при шифровании

Для GCM: проверьте nonce (должен быть 12 байт)



**Ошибка: "File not found"**
Причина: Указан несуществующий файл.
Решение:

1.Проверьте путь к файлу

2.Убедитесь, что у вас есть права на чтение файла

3.Используйте абсолютные пути для файлов в других директориях

## Лучшие практики безопасности

### Управление ключами
**Хорошо:**
- Генерируйте случайные ключи с помощью `os.urandom()`
- Храните ключи в защищенном хранилище (HSM, ключевой менеджер)
- Используйте разные ключи для разных целей
- Регулярно обновляйте ключи

**Избегайте:**
- Жестко заданных ключей в коде
- Ключей, полученных из простых паролей
- Повторного использования ключей
- Хранения ключей в открытом виде

### Выбор режима шифрования
**Используйте:**
- **GCM** - для большинства случаев (конфиденциальность + аутентификация)
- **CBC** или **CTR** - с отдельной аутентификацией (HMAC)

**Избегайте:**
- **ECB** - для реальных данных (раскрывает шаблоны)
- Неаутентифицированных режимов для чувствительных данных

### Работа с паролями
**Хорошо:**
- Используйте PBKDF2 с >100,000 итераций
- Добавляйте уникальную соль для каждого пароля
- Используйте пароли длиной >12 символов

**Избегайте:**
- Простых паролей (password123, qwerty)
- Маленького количества итераций PBKDF2
- Использования пароля напрямую как ключа

### Обработка данных
**Хорошо:**
- Проверяйте аутентификацию перед расшифровкой
- Очищайте чувствительные данные из памяти после использования
- Проверяйте целостность данных при передаче

**Избегайте:**
- Расшифровки без проверки аутентификации
- Логирования чувствительных данных
- Непроверенных данных от ненадежных источников
