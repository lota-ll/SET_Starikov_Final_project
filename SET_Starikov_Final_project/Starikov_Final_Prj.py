import random
import string
from cryptography.fernet import Fernet

# Генерація ключа для шифрування (збережіть цей ключ у безпечному місці)
# Якщо ключ вже є, завантажте його замість генерації
try:
    with open("key.key", "rb") as key_file:
        key = key_file.read()
except FileNotFoundError:
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

cipher = Fernet(key)


def generate_password(length=12):
    """
    Генерує складний пароль заданої довжини.

    :param length: Довжина пароля (мінімум 8 символів).
    :return: Згенерований пароль.
    """
    if length < 8:
        raise ValueError("Довжина пароля повинна бути не менше 8 символів.")

    # Набори символів для пароля
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_chars = string.punctuation

    # Щоб гарантувати складність, включимо по одному символу з кожного набору
    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(special_chars),
    ]

    # Заповнимо решту довжини випадковими символами з усіх наборів
    all_chars = lowercase + uppercase + digits + special_chars
    password += random.choices(all_chars, k=length - len(password))

    # Перемішаємо пароль, щоб уникнути передбачуваності
    random.shuffle(password)

    return "".join(password)


def save_password_to_file(password, service, filename="passwords.txt"):
    """
    Зберігає пароль у файл з коментарем.

    :param password: Збережений пароль.
    :param service: Назва сервісу або коментар.
    :param filename: Ім'я файлу.
    """
    with open(filename, "a") as file:
        file.write(f"{service}: {password}\n")
    print(f"Пароль для {service} збережено у файл {filename}.")


def view_saved_passwords(filename="passwords.txt"):
    """
    Виводить усі збережені паролі на екран.

    :param filename: Ім'я файлу.
    """
    try:
        with open(filename, "r") as file:
            print("\nЗбережені паролі:")
            for line in file:
                print(line.strip())
    except FileNotFoundError:
        print("Файл з паролями не знайдено.")


def save_password(service, password, filename="encrypted_passwords.txt"):
    """
    Функція для шифрування і збереження пароля.

    :param service: Назва сервісу.
    :param password: Пароль для збереження.
    :param filename: Ім'я файлу для збереження.
    """
    salt = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    salted_password = salt + password
    encrypted_password = cipher.encrypt(salted_password.encode())
    with open(filename, "a") as file:
        file.write(f"{service}: {salt}:{encrypted_password.decode()}\n")
    print(f"Пароль для {service} успішно зашифровано і збережено.")


def load_passwords(filename="encrypted_passwords.txt"):
    """
    Декодування і виведення збережених паролів.

    :param filename: Ім'я файлу із зашифрованими паролями.
    """
    try:
        with open(filename, "r") as file:
            print("\nЗбережені паролі:")
            for line in file:
                service, data = line.strip().split(": ")
                salt, encrypted_password = data.split(":")
                decrypted_password = cipher.decrypt(
                    encrypted_password.encode()
                ).decode()
                original_password = decrypted_password[len(salt) :]
                print(f"{service}: {original_password}")
    except FileNotFoundError:
        print("Файл із зашифрованими паролями не знайдено.")
    except Exception as e:
        print(f"Помилка при декодуванні: {e}")


def main_menu():
    """
    Відображає головне меню програми.
    """
    while True:
        print("\nМеню:")
        print("1. Згенерувати новий пароль")
        print("2. Зберегти пароль у файл (відкрито)")
        print("3. Переглянути відкриті збережені паролі")
        print("4. Зберегти пароль у файл (зашифровано)")
        print("5. Переглянути зашифровані збережені паролі")
        print("6. Вийти")

        choice = input("Оберіть дію (1-6): ")

        if choice == "1":
            try:
                length = int(input("Введіть довжину пароля (мінімум 8): "))
                password = generate_password(length)
                print(f"Ваш новий пароль: {password}")
            except ValueError as e:
                print(f"Помилка: {e}")
        elif choice == "2":
            password = input("Введіть пароль для збереження: ")
            service = input("Введіть назву сервісу або коментар: ")
            save_password_to_file(password, service)
        elif choice == "3":
            view_saved_passwords()
        elif choice == "4":
            password = input("Введіть пароль для шифрування і збереження: ")
            service = input("Введіть назву сервісу: ")
            save_password(service, password)
        elif choice == "5":
            load_passwords()
        elif choice == "6":
            print("Вихід із програми.")
            break
        else:
            print("Невірний вибір. Спробуйте ще раз.")


# Приклад використання
if __name__ == "__main__":
    main_menu()
