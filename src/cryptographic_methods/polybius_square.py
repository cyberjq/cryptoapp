from src.cryptographic_methods.exceptions import EncryptException, DecryptException

_KEY = (
    ("*", "(", ")", "<", ">", "–", "«", "»", "…", "№"),
    ("!", "?", ";", "а", "б", "в", "г", "д", "е", "ё"),
    ("р", "с", "т", "у", "ф", "х", "ц", "ч", "ш", "щ"),
    ("У", "Ф", "Х", "Ц", "Ч", "Ш", "Щ", "Ъ", "Ы", "Ь"),
    ("ж", "з", "и", "й", "к", "л", "м", "н", "о", "п"),
    ("Й", "К", "Л", "М", "Н", "О", "П", "Р", "С", "Т"),
    ("А", "Б", "В", "Г", "Д", "Е", "Ё", "Ж", "З", "И"),
    ("7", "8", "9", "X", "I", "#", "%", " ", ",", "."),
    ("Э", "Ю", "Я", "0", "1", "2", "3", "4", "5", "6"),
    ("ъ", "ы", "ь", "э", "ю", "я", "—", "\"", ":", "-")
)


def _get_encrypt_key(key: tuple = _KEY) -> dict[str, str]:
    encrypt_key = dict()

    for vertical_index in range(len(key)):
        for horizontal_index in range(len(key[vertical_index])):
            encrypt_key.update({str(key[vertical_index][horizontal_index]): f"{vertical_index}{horizontal_index}"})

    return encrypt_key


_ENCRYPT_KEY = _get_encrypt_key(_KEY)


def decrypt(text: str) -> str:
    if len(text) % 2 != 0:
        raise DecryptException("Не удалось расшифровать текст! Недостаточно данных")

    decrypt_text = ""

    for index in range(1, len(text), 2):
        vertical_index = int(text[index - 1])
        horizontal_index = int(text[index])
        decrypt_text += _KEY[vertical_index][horizontal_index]

    return decrypt_text


def encrypt(text: str) -> str:
    encrypt_text = ""
    for symbol in text:
        encrypt_symbol = _ENCRYPT_KEY.get(symbol)
        if not encrypt_symbol:
            raise EncryptException(f"Не удается закодировать символ \"{symbol}\"! Не содержится в ключе!")

        encrypt_text += encrypt_symbol

    return encrypt_text
