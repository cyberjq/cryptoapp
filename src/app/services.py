

def is_prime(x: int) -> bool:
    for i in range(2, (x // 2) + 1):
        if x % i == 0:
            return False
    return True
