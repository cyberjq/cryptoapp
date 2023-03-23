import array
import struct
from src.cryptographic_methods.sboxes import t1, t2, t3, t4


def _round(a, b, c, x, mul) -> tuple:
    c ^= x
    c &= 0xffffffffffffffff
    a -= t1[(c >> (0 * 8)) & 0xFF] ^ t2[(c >> (2 * 8)) & 0xFF] \
         ^ t3[(c >> (4 * 8)) & 0xFF] ^ t4[(c >> (6 * 8)) & 0xFF]
    b += t4[(c >> (1 * 8)) & 0xFF] ^ t3[(c >> (3 * 8)) & 0xFF] \
         ^ t2[(c >> (5 * 8)) & 0xFF] ^ t1[(c >> (7 * 8)) & 0xFF]
    b *= mul
    a &= 0xffffffffffffffff
    b &= 0xffffffffffffffff
    c &= 0xffffffffffffffff
    return a, b, c


def _pass(a, b, c, mul, mystr):
    a, b, c = _round(a, b, c, mystr[0], mul)
    a, b, c = _round(b, c, a, mystr[1], mul)
    a, b, c = c, a, b
    a, b, c = _round(c, a, b, mystr[2], mul)
    a, b, c = b, c, a
    a, b, c = _round(a, b, c, mystr[3], mul)
    a, b, c = _round(b, c, a, mystr[4], mul)
    a, b, c = c, a, b
    a, b, c = _round(c, a, b, mystr[5], mul)
    a, b, c = b, c, a
    a, b, c = _round(a, b, c, mystr[6], mul)
    a, b, c = _round(b, c, a, mystr[7], mul)
    a, b, c = c, a, b
    return a, b, c


def _compress(text_bytes: array.array, res: list[int]) -> None:
    """
    save_abc
    pass(a, b, c,5)
    key_schedule
    pass(c, a, b,7)
    key_schedule
    pass(b, c, a,9)
    feedforward
    """
    # setup
    a = res[0]
    b = res[1]
    c = res[2]

    x = []

    # по 64 бита
    for j in range(0, 8):
        x.append(struct.unpack('Q', text_bytes[j * 8:j * 8 + 8])[0])

    # save_abc
    aa = a
    bb = b
    cc = c
    allf = 0xFFFFFFFFFFFFFFFF

    for i in range(0, 3):
        # key_schedule генерация ключей, обратимая функция, которая отвечает за то,
        # чтобы изменение небольшого числа бит сообщения x вызвало изменение большого числа бит
        # на следующем выполнении pass:
        if i != 0:
            x[0] = (x[0] - (x[7] ^ 0xA5A5A5A5A5A5A5A5) & allf) & allf
            x[1] ^= x[0]
            x[2] = (x[2] + x[1]) & allf
            x[3] = (x[3] - (x[2] ^ (~x[1] & allf) << 19) & allf) & allf
            x[4] ^= x[3]
            x[5] = (x[5] + x[4]) & allf
            x[6] = (x[6] - (x[5] ^ (~x[4] & allf) >> 23) & allf) & allf
            x[7] ^= x[6]
            x[0] = (x[0] + x[7]) & allf
            x[1] = (x[1] - (x[0] ^ (~x[7] & allf) << 19) & allf) & allf
            x[2] ^= x[1]
            x[3] = (x[3] + x[2]) & allf
            x[4] = (x[4] - (x[3] ^ (~x[2] & allf) >> 23) & allf) & allf
            x[5] ^= x[4]
            x[6] = (x[6] + x[5]) & allf
            x[7] = (x[7] - (x[6] ^ 0x0123456789ABCDEF) & allf) & allf

        # pass(a, b, c, ...)
        if i == 0:
            a, b, c = _pass(a, b, c, 5, x)
        elif i == 1:
            a, b, c = _pass(a, b, c, 7, x)
        else:
            a, b, c = _pass(a, b, c, 9, x)

        a, c, b = c, b, a

    #feedforward
    a ^= aa
    b = (b - bb) & allf
    c = (c + cc) & allf

    # map values out
    res[0] = a
    res[1] = b
    res[2] = c


def hash(text: str) -> str:
    # a, b, c
    res = [0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187]
    i = 0
    text_len = len(text)
    text_bytes = array.array('B')
    text_bytes.frombytes(text[i:].encode())

    # Если текст из нескольких блоков по 512 бит
    while i < text_len - 63:
        _compress(text_bytes[i: i + 64], res)
        i += 64

    text_bytes = array.array('B')
    text_bytes.frombytes(text[i:].encode())

    # Расширение, добавляем один бит и 0 пока сообщение не станет длиной равной 448 по модулю 512
    text_bytes_len = len(text_bytes)
    text_bytes.append(0x01)
    text_bytes_len += 1

    while text_bytes_len & 7 != 0:
        text_bytes.append(0)
        text_bytes_len += 1

    if text_bytes_len > 56:
        while text_bytes_len < 64:
            text_bytes.append(0)
            text_bytes_len += 1
        _compress(text_bytes, res)
        text_bytes_len = 0

    # make the first 56 bytes 0
    text_bytes.extend([0 for i in range(0, 56 - text_bytes_len)])
    while text_bytes_len < 56:
        text_bytes[text_bytes_len] = 0
        text_bytes_len += 1
    while len(text_bytes) > 56:
        text_bytes.pop(56)

    text_bytes.frombytes(struct.pack('Q', text_len << 3))
    _compress(text_bytes, res)

    return f"{res[0]:0X}{res[1]:0X}{res[2]:0X}"


if __name__ == '__main__':
    text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789"
    print(len(text))
    print(hash(text))
