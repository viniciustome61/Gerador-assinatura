from parte1 import HASH_FUNCTION, encrypt, decrypt

def sign_message(message, private_key):
    """
    Assina uma mensagem usando a chave privada RSA.

    A assinatura é feita cifrando o hash da mensagem com a chave privada.
    Args:
        message (str): A mensagem a ser assinada.
        private_key (tuple): A chave privada RSA (d, n).

    Returns:
        int: A assinatura como um inteiro.
    """
    if isinstance(message, str):
        message = message.encode('utf-8')

    hash_msg = HASH_FUNCTION(message)
    # A "cifragem" do hash com a chave privada é conceitualmente uma operação de assinatura
    signature = encrypt(hash_msg, private_key)
    return signature


def verify_signature(message, signature, public_key):
    """
    Verifica a assinatura de uma mensagem usando a chave pública RSA.

    Args:
        message (str): A mensagem original.
        signature (int): A assinatura a ser verificada.
        public_key (tuple): A chave pública RSA (e, n).

    Returns:
        bool: True se a assinatura for válida, False caso contrário.
    """
    if isinstance(message, str):
        message = message.encode('utf-8')

    hash_msg_original = HASH_FUNCTION(message)

    # A "decifragem" da assinatura com a chave pública recupera o hash
    hash_from_signature = decrypt(signature, public_key)

    return hash_msg_original == hash_from_signature