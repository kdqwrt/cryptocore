#!/usr/bin/env python3
"""
Запуск всех тестов cryptocore
"""

import os
import sys
import importlib.util


def run_test_file(test_file):
    """Запускает один тестовый файл"""
    print(f"\n{'=' * 60}")
    print(f"Запуск: {test_file}")
    print("=" * 60)

    try:
        # Специальные настройки для каждого теста
        if test_file == "test_m2.py":
            # test_m2.py нужно запускать из директории tests
            original_cwd = os.getcwd()
            tests_dir = os.path.join(os.path.dirname(__file__), 'tests')
            os.chdir(tests_dir)

            # Импортируем и запускаем
            spec = importlib.util.spec_from_file_location("test_m2", "test_m2.py")
            module = importlib.util.module_from_spec(spec)
            sys.modules["test_m2"] = module
            spec.loader.exec_module(module)

            # Запускаем функцию run_milestone2_tests()
            success = module.run_milestone2_tests()
            os.chdir(original_cwd)
            return success

        else:
            # Для остальных тестов просто импортируем и запускаем
            test_path = os.path.join('tests', test_file)
            spec = importlib.util.spec_from_file_location("test_module", test_path)
            module = importlib.util.module_from_spec(spec)

            # Сохраняем оригинальные аргументы
            original_argv = sys.argv.copy()
            sys.argv = [test_path]

            try:
                spec.loader.exec_module(module)

                # Если есть функция main() - вызываем ее
                if hasattr(module, 'main'):
                    result = module.main()
                    if isinstance(result, bool):
                        return result
                    elif isinstance(result, int):
                        return result == 0
                    else:
                        return True
                else:
                    # Если нет main(), просто считаем успешным если нет исключений
                    return True

            finally:
                sys.argv = original_argv

    except SystemExit as e:
        return e.code == 0
    except Exception as e:
        print(f"Ошибка при запуске {test_file}: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Основная функция запуска"""

    # Проверяем, что мы в правильной директории
    if not os.path.exists('tests'):
        print("Ошибка: директория 'tests' не найдена!")
        print("Запустите из корневой директории проекта")
        return False

    # Список всех тестовых файлов
    test_files = [
        "test_salt.py",
        "test_hkdf.py",
        "test_pbkdf2.py",
        "test_hash.py",
        "test_hmac.py",
        "test_ecb.py",
        "test_m2.py",
        "test_gcm.py",
        "test_cli.py",
        "test_csprng.py"
    ]

    print(" ЗАПУСК ВСЕХ ТЕСТОВ ")
    print("=" * 60)

    results = []

    for test_file in test_files:
        test_path = os.path.join('tests', 'unit', test_file)

        if not os.path.exists(test_path):
            print(f"  Тест не найден: {test_file}")
            continue

        success = run_test_file(test_file)
        status = " УСПЕХ" if success else " ОШИБКА"
        print(f"\n{status}: {test_file}")
        results.append((test_file, success))

    # Вывод итогов
    print(f"\n{'=' * 60}")
    print("ИТОГОВАЯ СВОДКА:")
    print("=" * 60)

    passed = sum(1 for _, success in results if success)
    total = len(results)

    for test_file, success in results:
        status = "" if success else ""
        print(f"{status} {test_file}")

    print(f"\n РЕЗУЛЬТАТ: {passed}/{total} тестов пройдено")

    if passed == total:
        print(" ВСЕ ТЕСТЫ УСПЕШНО ПРОЙДЕНЫ!")
        return True
    else:
        print(f" {total - passed} тестов не пройдено")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)