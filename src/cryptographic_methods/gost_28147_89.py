_SBOX = (
    (15, 12, 5, 2, 11, 3, 9, 5, 4, 11, 15, 4, 10, 12, 13, 3),
    (4, 3, 11, 12, 7, 8, 13, 15, 7, 15, 1, 4, 7, 5, 15, 6),
    (5, 7, 12, 8, 14, 15, 15, 8, 9, 14, 15, 12, 9, 9, 3, 15),
    (10, 6, 13, 4, 15, 15, 10, 12, 4, 15, 6, 10, 13, 14, 2, 7),
    (1, 3, 15, 8, 9, 8, 13, 9, 1, 5, 4, 15, 15, 15, 11, 8),
    (10, 15, 8, 14, 12, 1, 1, 9, 13, 11, 7, 8, 14, 4, 9, 13),
    (4, 4, 13, 9, 4, 8, 15, 5, 14, 9, 5, 10, 4, 8, 5, 5),
    (4, 4, 2, 9, 6, 13, 4, 4, 14, 5, 3, 5, 13, 7, 3, 15)
)


def _get_out(inright: int, sub_key: int) -> int:
    out = 0
    temp = (inright + sub_key) % (1 << 32)
    # Сдвиг суммы ключа и правой позиции
    for i in range(8):
        phonetic = (temp >> (4 * i)) & 0b1111
        '''
        Определение ячейки
        Сдвиг на n бит и выбор пересечения
        '''
        out |= (_SBOX[i][phonetic] << (4 * i))
        '''
        Второй бит устанавливается в 0
        Сдвиг влево на n бит
        '''
    out = ((out >> 21) | (out << 11)) & 0xFFFFFFFF
    # Пересечение бита и объединения множеств со сдвигами
    return out


def _crypt_operation(inleft: int, inright: int, sub_key: int) -> tuple[int, int]:
    outleft = inright
    # Присваиваем левому выходу правые входные данные
    outright = inleft ^ _get_out(inright, sub_key)
    # Исключаем пересечение
    return outleft, outright


def _decrypt_operation(inleft: int, inright: int, sub_key: int) -> tuple[int, int]:
    outleft = inright ^ _get_out(inleft, sub_key)
    # Присваиваем левому выходу правые входные данные
    outright = inleft
    # Исключаем пересечение
    return outleft, outright


def _get_sub_keys(key: int) -> list[int]:
    sub_keys = [0] * 8
    for i in range(8):
        # Пересечние сдвига ключа вправо на 32 бита с десятизначным числом
        sub_keys[i] = (key >> (32 * i)) & 0xFFFFFFFF
    return sub_keys


def _crypt_block(text: str, sub_keys: list[int], codec: str = "cp1251") -> int:
    text = int(text.encode(codec).hex(), 16)
    # text = self.msg_to_number(text)
    text_left = text >> 32
    text_right = text & 0xFFFFFFFF
    # Разбитие текста с помощью побитового сдвига
    for q in range(24):
        text_left, text_right = _crypt_operation(text_left, text_right, sub_keys[q % 8])
    for q in range(8):
        text_left, text_right = _crypt_operation(text_left, text_right, sub_keys[7 - q])
    # 32 цикла с различными ключами
    return (text_left << 32) | text_right


def encrypt(text: str, key: int, codec: str = "cp1251") -> str:
    sub_keys = _get_sub_keys(key=key)
    n = 8
    encrypt_text = ""
    for i in range(0, len(text), n):
        encrypt_text += f"{_crypt_block(text[i:i + n], sub_keys, codec)}".zfill(20)

    return encrypt_text


def _decrypt_block(code: int, sub_keys: list[int]) -> int:
    text_left = code >> 32
    text_right = code & 0xFFFFFFFF

    for q in range(8):
        text_left, text_right = _decrypt_operation(text_left, text_right, sub_keys[q])
    for q in range(24):
        text_left, text_right = _decrypt_operation(text_left, text_right, sub_keys[(7 - q) % 8])

    return (text_left << 32) | text_right


def decrypt(encrypt_text: str, key: int, codec: str = "cp1251") -> str:
    sub_keys = _get_sub_keys(key=key)
    n = 20
    text = ""
    for i in range(0, len(encrypt_text), n):
        chunk = encrypt_text[i:i + n]
        _hex = hex(_decrypt_block(int(chunk), sub_keys))[2:]
        text += bytes.fromhex(_hex).decode(codec)

    return text


def mac(text: str, key: int) -> int:
    sub_keys = _get_sub_keys(key)
    n = 8
    _mac = 0

    for i in range(0, len(text), n):
        chunk = text[i:i + n]

        chunk = int(chunk.encode('utf-8').hex(), 16)
        text_left = chunk >> 32
        text_right = chunk & 0xFFFFFFFF
        # Разбитие текста с помощью побитового сдвига
        for q in range(16):
            text_left, text_right = _crypt_operation(text_left, text_right, sub_keys[q % 8])

        numb_msg = (text_left << 32) | text_right
        _mac = _mac ^ numb_msg

    return _mac & 0x00000000FFFFFFFF


def is_valid_text(decrypt_text: str, key: int, encrypt_mac: int) -> bool:
    return encrypt_mac == mac(decrypt_text, key)







if __name__ == '__main__':
    key = 45839695895184572594857967124356450966362023091609802819950324423807592810760
    hash = encrypt(' великим книге, другой? нужно, что', key)
    print(hash)
    print(decrypt(hash, key))
    _mac = mac(' великим книге, другой? нужно, что', key)
    print("Имитовставка:", _mac)
    print("Сообщения валидные" if is_valid_text(decrypt(hash, key), key, _mac) else "Сообщения не валидные")

