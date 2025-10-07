import random
import hashlib
import os
from math import ceil
# Importação necessária para o formato PEM
from Crypto.PublicKey import RSA    

# Constantes
HASH_FUNCTION = lambda x: hashlib.sha3_256(x).digest()
HASH_LENGTH = len(HASH_FUNCTION(b''))


def generate_large_prime(bits=1024):
    """
    Gera um número primo de um tamanho de bits especificado.

    Utiliza um teste de primalidade probabilístico de Miller-Rabin.
    Args:
        bits (int): O número de bits que o primo deve ter.

    Returns:
        int: Um número provavelmente primo.
    """
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1  # Garante que seja ímpar e tenha o bit mais significativo
        if miller_rabin_test(candidate):
            return candidate


def miller_rabin_test(n, k=20):
    """
    Realiza o teste de primalidade de Miller-Rabin em um número.

    Args:
        n (int): O número a ser testado.
        k (int): O número de iterações (testes) a serem realizadas.

    Returns:
        bool: True se n for provavelmente primo, False caso contrário.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def modular_inverse(a, m):
    """
    Calcula o inverso modular de a (mod m) usando o Algoritmo de Euclides Estendido.

    Args:
        a (int): O número para o qual encontrar o inverso.
        m (int): O módulo.

    Returns:
        int: O inverso modular de a.
    """
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


def generate_keys(key_size=1024):
    """
    Gera um par de chaves RSA (pública e privada).

    Args:
        key_size (int): O tamanho em bits para os números primos (p e q).

    Returns:
        dict: Um dicionário contendo a chave pública (e, n) e a chave privada (d, n).
    """
    p = generate_large_prime(key_size)
    q = generate_large_prime(key_size)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # Expoente público comum por ser primo e eficiente.
    d = modular_inverse(e, phi)

    return {
        'public_key': (e, n),
        'private_key': (d, n),
    }


def mgf1(seed, length):
    """
    Função de Geração de Máscara (MGF1) baseada em uma função de hash.

    Args:
        seed (bytes): A semente para a geração da máscara.
        length (int): O comprimento desejado da máscara em bytes.

    Returns:
        bytes: A máscara gerada.
    """
    if length > (2**32 * HASH_LENGTH):
        raise ValueError("Máscara muito longa")

    T = b''
    for counter in range(ceil(length / HASH_LENGTH)):
        C = counter.to_bytes(4, 'big')
        T += HASH_FUNCTION(seed + C)
    return T[:length]


def oaep_pad(message, n):
    """
    Aplica o preenchimento OAEP (Optimal Asymmetric Encryption Padding) a uma mensagem.

    Args:
        message (bytes): A mensagem a ser preenchida.
        n (int): O módulo RSA, usado para determinar o comprimento do bloco.

    Returns:
        bytes: A mensagem com o preenchimento OAEP.
    """
    k = (n.bit_length() + 7) // 8  # Comprimento de n em bytes
    mLen = len(message)

    if mLen > k - 2 * HASH_LENGTH - 2:
        raise ValueError("Mensagem muito longa para o preenchimento OAEP")

    lHash = HASH_FUNCTION(b'')
    PS = b'\x00' * (k - mLen - 2 * HASH_LENGTH - 2)
    DB = lHash + PS + b'\x01' + message

    seed = os.urandom(HASH_LENGTH)
    dbMask = mgf1(seed, k - HASH_LENGTH - 1)
    maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))

    seedMask = mgf1(maskedDB, HASH_LENGTH)
    maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))

    return b'\x00' + maskedSeed + maskedDB


def oaep_unpad(padded, n):
    """
    Remove o preenchimento OAEP de uma mensagem.

    Args:
        padded (bytes): A mensagem com preenchimento.
        n (int): O módulo RSA.

    Returns:
        bytes: A mensagem original.
    """
    k = (n.bit_length() + 7) // 8
    if len(padded) != k or padded[0] != 0:
        raise ValueError("Erro de decodificação OAEP")

    maskedSeed = padded[1:HASH_LENGTH + 1]
    maskedDB = padded[HASH_LENGTH + 1:]

    seedMask = mgf1(maskedDB, HASH_LENGTH)
    seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))

    dbMask = mgf1(seed, k - HASH_LENGTH - 1)
    DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))

    lHash = HASH_FUNCTION(b'')
    if not DB.startswith(lHash):
        raise ValueError("Erro de decodificação OAEP")

    i = HASH_LENGTH
    while i < len(DB):
        if DB[i] == 1:
            return DB[i + 1:]
        if DB[i] != 0:
            raise ValueError("Erro de decodificação OAEP")
        i += 1
    raise ValueError("Erro de decodificação OAEP")


def encrypt(message, public_key):
    """
    Cifra uma mensagem usando RSA com preenchimento OAEP.

    Args:
        message (str or bytes): A mensagem a ser cifrada.
        public_key (tuple): A chave pública RSA (e, n).

    Returns:
        int: O texto cifrado como um inteiro.
    """
    e, n = public_key
    if isinstance(message, str):
        message = message.encode('utf-8')

    padded = oaep_pad(message, n)
    m_int = int.from_bytes(padded, 'big')
    c_int = pow(m_int, e, n)
    return c_int


def decrypt(ciphertext, private_key):
    """
    Decifra uma mensagem usando RSA com preenchimento OAEP.

    Args:
        ciphertext (int): O texto cifrado como um inteiro.
        private_key (tuple): A chave privada RSA (d, n).

    Returns:
        str or bytes: A mensagem original decifrada.
    """
    d, n = private_key
    m_int = pow(ciphertext, d, n)
    k = (n.bit_length() + 7) // 8
    em = m_int.to_bytes(k, 'big')

    message = oaep_unpad(em, n)

    try:
        return message.decode('utf-8')
    except UnicodeDecodeError:
        return message

# --- NOVAS FUNÇÕES ---

def save_key_to_pem(key_tuple, filename, is_private=True):
    """
    Salva uma chave RSA (pública ou privada) num ficheiro em formato PEM.

    Args:
        key_tuple (tuple): A chave a ser salva, (e, n) para pública ou (d, n) para privada.
        filename (str): O nome do ficheiro onde salvar a chave.
        is_private (bool): True se a chave for privada, False se for pública.
    """
    if is_private:
        d, n = key_tuple
        e = 65537 # Precisamos do 'e' para reconstruir a chave privada
        rsa_key = RSA.construct((n, e, d))
        key_data = rsa_key.export_key()
    else:
        e, n = key_tuple
        rsa_key = RSA.construct((n, e))
        key_data = rsa_key.export_key()

    with open(filename, 'wb') as f:
        f.write(key_data)
    print(f"Chave salva em '{filename}'")

def load_key_from_pem(filename):
    """
    Carrega uma chave RSA de um ficheiro PEM.

    Args:
        filename (str): O nome do ficheiro da chave.

    Returns:
        tuple: A chave no formato (componente1, componente2). (e, n) para pública, (d, n) para privada.
    """
    with open(filename, 'rb') as f:
        rsa_key = RSA.import_key(f.read())
    
    if rsa_key.has_private():
        return (rsa_key.d, rsa_key.n)
    else:
        return (rsa_key.e, rsa_key.n)