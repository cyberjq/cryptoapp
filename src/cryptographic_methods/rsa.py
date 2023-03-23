import random


def get_keys(p: int = None, q: int = None) -> tuple[tuple[int, int], tuple[int, int]]:
    if p is None and q is None:
        prime_numbers = _get_prime_numbers()
        p = prime_numbers[random.randint(0, len(prime_numbers) - 1)]
        q = prime_numbers[random.randint(0, len(prime_numbers) - 1)]
        while q == p:
            q = prime_numbers[random.randint(0, len(prime_numbers) - 1)]

    n = p * q
    f = (p - 1) * (q - 1)  # Функция Эйлера

    e = _get_e(f)  # Открытая экспонента
    d = _get_d(e, f)  # Секретная экспонента

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


def _fast_mul(a: int, b: int, n: int) -> int:
    res = 1
    while b != 0:
        if b % 2 == 0:
            b = b / 2
            a = (a * a) % n
        elif b % 2 != 0:
            b = b - 1
            res = (res * a) % n
    return res


def _get_prime_numbers(n: int = 1000) -> list[int]:
    numbers = [i for i in range(n + 1) if i % 2 != 0]
    numbers[1] = 0
    prime_numbers = []

    i = 2
    while i <= n:
        if numbers[i] != 0:
            prime_numbers.append(numbers[i])
            for j in range(i, n + 1, i):
                numbers[j] = 0
        i += 1
    return prime_numbers


def _get_d(e: int, f: int) -> int:
    def gcdex(a, b):
        if b == 0:
            return a, 1, 0
        else:
            d, x, y = gcdex(b, a % b)
            return d, y, x - y * (a // b)

    nod = gcdex(e, f)
    return (nod[1] % f + f) % f


def _get_e(f: int) -> int:
    e = 1
    e_tmp = 1
    f_n_tmp = f

    while (e_tmp + f_n_tmp) != 1:
        e = random.randint(3, f)
        e_tmp = e
        f_n_tmp = f
        while e_tmp != 0 and f_n_tmp != 0:
            if e_tmp > f_n_tmp:
                e_tmp = e_tmp % f_n_tmp
            else:
                f_n_tmp = f_n_tmp % e_tmp

    return e


def encrypt(text: str, public_key: tuple[int, int], codec: str = "cp1251") -> str:
    """
    :param public_key: (e, n)
    """
    encrypt_text = ""
    for symbol in text.encode(codec):
        encrypt_text += f"{_fast_mul(symbol, public_key[0], public_key[1])}".zfill(7)

    return encrypt_text


def decrypt(encrypt_text: str, private_key: tuple[int, int], codec: str = "cp1251") -> str:
    """
        :param public_key: (d, n)
    """
    n = 7
    _bytes = []
    for i in range(0, len(encrypt_text), n):
        chunk = encrypt_text[i:i + n]
        _bytes.append(_fast_mul(int(chunk), private_key[0], private_key[1]))

    return bytes(_bytes).decode(codec)


if __name__ == "__main__":
    public_key, private_key = get_keys(1229, 1783)
    # public_key, private_key = (37897, 1510441), (238153, 1510441)
    print(public_key, private_key)
    message = "Веленью божию, о муза, будь послушна, Обиды не страшась, не требуя венца,"
    encrypt_message = encrypt(message, public_key, "utf-8")
    print('Зашифрованное сообщение: {}'.format(encrypt_message))
    decrypt_message = decrypt(encrypt_message, private_key, "utf-8")
    print('Расшифрованное сообщение: {}'.format(decrypt_message))
    # text = "0932888095129009638600951290018466312468130746187130376602359520056915081389212370980746187107504313037660056915130376607020150092983005289811072731075043130376602359520092983041665912468131303766026041800569150984107096386000929830627383018466311072731075043130376609693740235952123709804166590275623130376601846630951290130376609841070813682035652911072730627383110727309841071246813107504313037660184663095129013037660813682035652909512900235952009298308547281303766056542209512900184663032846611072731075043"
    # print(decrypt(text, (246453, 1510441)))
