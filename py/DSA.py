import random as r


# implementation of DSA

def num_is_prime(num):
    if (num <= 3) or (num % 2 == 0):
        return num == 2 or num == 3

    divisor = 3
    while (divisor <= num ** 0.5) and (num % divisor != 0):
        divisor += 2

    return num % divisor != 0


def find_prime_pair(min, max):
    p = 0

    while not num_is_prime(p):
        p = r.randint(min, max)

    p_decremented = p - 1

    q = 1
    while not (p_decremented % q == 0 and num_is_prime(q)):
        q = r.randint(min / 100, p_decremented)

    return p, q


def mod_inv(a, mod):
    i = 1
    while i < mod:
        if ((a % mod) * (i % mod)) % mod == 1:
            break
        i += 1
    return i


# mod exponentiation with right to left binary method
def mod_pow(a, ex, mod):
    if mod == 1:
        return 0

    res = 1

    a = a % mod

    while ex > 0:
        if (ex % 2 == 1):
            res = ((res % mod) * (a % mod)) % mod

        ex = ex >> 1
        a = (a * a) % mod

    return res


# find element g
def find_element_g(p, q):
    for h in range(2, p):
        g = mod_pow(h, int((p - 1) / q), p)
        if g > 1:
            return g


# generate key pair
def generate_key_pair(p, q, g):
    sk = r.randint(1, q - 1)

    pk = mod_pow(g, sk, p)
    return sk, pk


def pick_k(q):
    return r.randint(1, q - 1)


def calculate_r(g, k, p, q):
    return mod_pow(g, k, p) % q


def calculate_s(k, r, sk, hash, q):
    return (hash + r * sk) * mod_inv(k, q) % q


# verify

def calculate_w(s, q):
    return mod_inv(s, q)


def calculate_u(w, hash, q):
    return (w * hash) % q


def calculate_v(w, r, q):
    return (w * r) % q


def calculate_z(g, u, pk, v, p, q):
    return ((mod_pow(g, u, p) * mod_pow(pk, v, p)) % p) % q
