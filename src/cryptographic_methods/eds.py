from src.cryptographic_methods import tiger, rsa


def generate_eds(text: str, private_key: tuple[int, int]) -> str:
    _hash = tiger.hash(text)
    _eds = rsa.encrypt(_hash, private_key)
    return _eds

def verify_eds(text: str, eds: str, public_key: tuple[int, int]) -> bool:
    _hash = tiger.hash(text)
    decrypt = rsa.decrypt(eds, public_key)
    return _hash == decrypt


# public_key, secret_key = rsamy.get_keys(1229, 1783)
#
# message = "Опалева"
# h = tiger.hash(message)
# print("Хеш-образ: {}".format(h))
# encrypt = rsamy.encrypt(h, secret_key)
#
# print('Зашифрованный хеш: {}'.format(encrypt))
#
#
# decrypt = rsamy.decrypt(encrypt, public_key)
# print('Расшифрованный хеш-образ: {}'.format(decrypt))

# # if h == hash_message:
# #     print(
# #         'Цифровая подпись подтверждена. Хеш-образы совпадают:\n (расчитанная Алисой) {} = {} (расшифрованная Алисой)'.format(
# #             h, hash_message))
# #
# # else:
# #     print(
# #         'Цифровая подпись не подтверждена. Хеш-образы не совпадают:\n (расчитанная Алисой) {} = {} (расшифрованная Алисой)'.format(
# #             h, hash_message))
# #
# input()
