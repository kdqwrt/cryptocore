# cryptocore

Командная утилита для шифрования и дешифрования файлов с использованием AES-128 в различных режимах работы, вычисления криптографических хешей, HMAC и безопасного выведения ключей.

## Возможности

- **Поддержка 7 режимов шифрования**: ECB, CBC, CFB, OFB, CTR, GCM (аутентифицированный), ETM (Encrypt-then-MAC)
- **Криптографические хеш-функции**: SHA-256 и SHA3-256 для проверки целостности данных
- **HMAC (Hash-based Message Authentication Code)**: Аутентификация сообщений с использованием SHA-256
- **Аутентифицированное шифрование (AEAD)**: GCM и Encrypt-then-MAC режимы с поддержкой AAD
- **Безопасная генерация IV/Nonce/Salt**: Автоматическая генерация криптографически безопасных значений
- **Автоматическая генерация ключей**: Ключ опционален для шифрования
- **Проверка слабых ключей**: Предупреждения при использовании потенциально слабых ключей
- **Безопасное выведение ключей (KDF)**:
    - **PBKDF2-HMAC-SHA256**: Выведение ключей из паролей с использованием соли и множества итераций
    - **HKDF (иерархия ключей)**: Детерминированное выведение множества ключей из мастер-ключа

## Инструкции по сборке
```bash
sudo apt install git

sudo apt update

sudo apt install python3-venv python3-pip python3-full

git clone https://github.com/kdqwrt/cryptocore.git

python3 -m venv venv

source venv/bin/activate

cd cryptocore

dir 

pip install --upgrade pip

pip install -e .

pip install setuptools wheel

python all_tests.py
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


cryptocore encrypt --mode cbc --encrypt --key @00112233445566778899aabbccddeeff --input test.txt --output encrypted.bin
cryptocore encrypt --mode cbc --decrypt --key @00112233445566778899aabbccddeeff --input encrypted.bin --output decrypted.txt

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
cryptocore derive --password "пароль" --salt a1b2c3d4e5f6 --iterations 100000 --length 16
```
## Структура проекта
```
pythonProject9/
├── src/
│ └── cryptocore/
│ ├── init.py
│ ├── aead.py
│ ├── cli.py
│ ├── csprng.py
│ ├── file_io.py
│ ├── hash/
│ │ ├── init.py
│ │ ├── sha256.py
│ │ └── sha3_256.py
│ ├── kdf/
│ │ ├── init.py
│ │ ├── hkdf.py
│ │ └── pbkdf2.py
│ ├── mac/
│ │ ├── init.py
│ │ └── hmac.py
│ └── modes/
│ ├── init.py
│ ├── cbc.py
│ ├── cfb.py
│ ├── ctr.py
│ ├── ecb.py
│ ├── gcm.py
│ └── ofb.py
├── tests/
│ ├── init.py
│ └── unit/
│ ├── init.py
│ ├── test_cli.py
│ ├── test_csprng.py
│ ├── test_ech.py
│ ├── test_gcm.py
│ ├── test_hash.py
│ ├── test_hkdf.py
│ ├── test_hmac.py
│ ├── test_m2.py
│ ├── test_pbkdf2.py
│ └── test_salt.py
├── all_test.py
├── requirements.txt
└── setup.py

````




# Использование
**Базовые команды**

Утилита поддерживает три основные команды:

**Шифрование/дешифрование**
```bash
python -m cryptocore.cli encrypt --mode <режим> --encrypt|--decrypt <опции>
```
**Хеширование и HMAC**
```bash
python -m cryptocore.cli dgst --algorithm <алгоритм> <опции>
```

**Выведение ключей**
```bash
python -m cryptocore.cli derive --password <пароль> <опции>
```

## Используемые стандарты
- **FIPS 197**: Advanced Encryption Standard (AES) - базовый алгоритм шифрования
- **FIPS 180-4**: Secure Hash Standard (SHA-256) - хеш-функция
- **FIPS 202**: SHA-3 Standard (SHA3-256) - современная хеш-функция
- **RFC 2104**: HMAC: Keyed-Hashing for Message Authentication - HMAC алгоритм
- **RFC 2898**: PKCS #5: Password-Based Cryptography Specification (PBKDF2) - выведение ключей из паролей
- **RFC 6070**: PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors - тестовые векторы
- **RFC 4231**: Test Vectors for HMAC-SHA-256 - тестовые векторы HMAC

# Другие стандарты
-**PKCS #7**: Cryptographic Message Syntax - схема дополнения (padding)


## Безопасность
**Криптографически стойкий CSPRNG**
- **Использует os.urandom() - криптографически стойкий генератор**
- **Генерация ключей, IV, nonce и солей**
- **Статистическая проверка качества**

**Проверка слабых ключей**
- **Обнаружение ключей со всеми нулями**
- **Обнаружение последовательных байтов**
- **Предупреждения пользователя**

**Катастрофический отказ**
- **При неудачной аутентификации (GCM, ETM) данные не выводятся**
- **Защита от утечки информации при атаках**

**Безопасное управление памятью**
- **Очистка чувствительных данных после использования**
- **Потоковая обработка больших файлов**


## Типы тестов
- Модульные тесты: Тестирование отдельных функций

- Интеграционные тесты: Тестирование взаимодействия компонентов

- Тесты интероперабельности: Совместимость с OpenSSL

- Тесты с официальными векторами: Проверка по NIST/RFC тест-векторам

