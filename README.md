Лабораторная работа по защите информации (Windows)
-----------------------------------

Проект представляет из себя десктопное приложение на PyQT, которое реализует криптографические методы:
1. Квадрат Полибия с заданным ключом
2. ГОСТ 28147 98 с простой заменой и выработки имитовставки
3. RSA
4. Хеширование методом Tiger 192 бита
5. Генерирование цифровой подписи на основе RSA

Быстрый старт
-----------------------------------
1. Клонировать проект к себе `git clone project_url`
2. Развернуть виртуальное пространство python `python -m venv venv_name` 
   или `python3 -m venv venv_name` (Linux) в директории проекта 
   и войти в него
3. Установить все зависимости из файла `requirements.txt`
4. Запустить файл `run_app.py` или `src/app/main.py`