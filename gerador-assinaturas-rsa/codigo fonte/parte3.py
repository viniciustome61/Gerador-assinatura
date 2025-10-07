import base64
from parte2 import verify_signature

def parse_signed_document(signed_document):
    """
    Analisa um documento assinado e formatado em Base64.

    Args:
        signed_document (str): O documento em formato Base64.

    Returns:
        tuple: Uma tupla contendo a mensagem original (str) e a assinatura (int).
    """
    try:
        decoded_data = base64.b64decode(signed_document)

        # Extrai o comprimento da mensagem (primeiros 4 bytes)
        message_length = int.from_bytes(decoded_data[:4], 'big')

        # Extrai a mensagem e a assinatura com base no comprimento
        message_end = 4 + message_length
        message = decoded_data[4:message_end].decode('utf-8')
        signature = int.from_bytes(decoded_data[message_end:], 'big')

        return message, signature
    except Exception as e:
        raise ValueError(f"Erro ao analisar o documento assinado: {e}")


def verify_signed_document(signed_document, public_key):
    """
    Verifica a validade de um documento assinado.

    Args:
        signed_document (str): O documento assinado em Base64.
        public_key (tuple): A chave pública RSA (e, n).

    Returns:
        tuple: Um booleano indicando validade e a mensagem original ou uma mensagem de erro.
    """
    try:
        message, signature = parse_signed_document(signed_document)
        is_valid = verify_signature(message, signature, public_key)
        
        if is_valid:
            return True, message
        else:
            return False, "Assinatura inválida."
            
    except ValueError as e:
        return False, str(e)