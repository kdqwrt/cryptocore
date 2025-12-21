# Руководство разработчика CryptoCore

## Настройка среды разработки

### Предварительные требования
- Python 3.8 или выше
- git
- virtualenv 

### Первоначальная настройка

```bash
# 1. Клонировать репозиторий
git clone https://github.com/yourusername/cryptocore.git
cd cryptocore

# 2. Создать виртуальное окружение
python3 -m venv venv

# 3. Активировать виртуальное окружение
# Для Linux/Mac:
source venv/bin/activate
# Для Windows:
 venv\Scripts\activate

# 4. Установить зависимости для разработки
pip install -e 

```

### Зависимости для разработки

Файл `requirements.txt`:
```
pycryptodome>=3.14.0
pytest>=7.0.0
```

## Структура проекта

```
pythonProject9/
├── src/
│   └── cryptocore/
│       ├── hash/
│       │   ├── sha256.py          # SHA-256 реализация
│       │   ├── sha3_256.py        # SHA3-256 реализация
│       │   └── __init__.py
│       ├── mac/
│       │   ├── hmac.py            # HMAC реализация с тестами RFC 4231
│       │   └── __init__.py
│       ├── modes/
│       │   ├── ecb.py             # ECB режим
│       │   ├── cbc.py             # CBC режим
│       │   ├── cfb.py             # CFB режим
│       │   ├── ofb.py             # OFB режим
│       │   ├── ctr.py             # CTR режим
│       │   ├── gcm.py             # GCM режим
│       │   └── __init__.py
│       ├── kdf/
│       │   ├── pbkdf2.py          # PBKDF2 реализация
│       │   ├── hkdf.py            # HKDF реализация
│       │   └── __init__.py
│       ├── __init__.py
│       ├── aead.py
│       ├── cli.py                 # Основной CLI интерфейс
│       ├── csprng.py
│       └── file_io.py
├── tests/
│   ├── unit/                      
│   │   ├── __init__.py
│   │   ├── test_cli.py
│   │   ├── test_csprng.py        # Тесты для csprng.py
│   │   ├── test_ech.py           # Тесты для ECB/OFB режимов
│   │   ├── test_gcm.py           # Тесты для GCM режима
│   │   ├── test_hash.py          # Тесты для хэш-функций
│   │   ├── test_hkdf.py          # Тесты для HKDF
│   │   ├── test_hmac.py          # Тесты для HMAC
│   │   ├── test_m2.py            # Тесты для MAC и режимов шифрования
│   │   ├── test_pbkdf2.py        # Тесты для PBKDF2
│   │   └── test_salt.py          # Тесты для солевых генераторов
│   └── __init__.py
├── all_test.py                    # Главный файл для запуска всех тестов
├── requirements.txt
└── setup.py
```


## Тестирование

### Запуск всех тестов

```bash
# Запуск всех тестов из одного файла
python all_tests.py
```



### Формат CHANGELOG.md

```markdown
# Журнал изменений

## [1.2.0] - 2024-01-15

### Добавлено
- Поддержка нового алгоритма
- Дополнительные тестовые векторы

### Изменено
- Улучшена производительность GCM
- Обновлены зависимости

### Исправлено

- Обработка ошибок в CLI
```



## Отладка

### Распространенные проблемы

1. **Ошибка импорта**
```bash
# Добавить cryptocore в PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

2. **Проблемы с зависимостями**
```bash
# Очистка и переустановка
pip uninstall -y cryptocore
pip install -e .
```

3. **Проблемы с тестами**
```bash
# Запуск в режиме отладки
```




### Установка из исходников

```bash
# Для пользователей
git clone https://github.com/yourusername/cryptocore.git
cd cryptocore
pip install .

# Или напрямую
pip install git+https://github.com/yourusername/cryptocore.git
```

## Поддержка

### Получение помощи

1. **Проверить документацию**
```bash
python -m pydoc cryptocore
```

2. **Запустить тесты для диагностики**
```bash
python all_tests.py --verbose
```

3. **Создать минимальный воспроизводимый пример**

### Сообщение об ошибках

Включить в отчет:
- Версию Python и cryptocore
- Команду, вызвавшую ошибку
- Полный traceback
- Пример входных данных (если возможно)

---

**Совет:** Всегда работайте в виртуальном окружении и регулярно запускайте `python all_tests` перед коммитами.

