import base64
from parte1 import generate_keys, save_key_to_pem, load_key_from_pem
from parte2 import sign_message
from parte3 import verify_signed_document
import os

def main():
    """
    Função principal que demonstra o fluxo de geração, salvamento,
    carregamento, assinatura e verificação.
    """
    private_key_file = "chave_privada.pem"
    public_key_file = "chave_publica.pem"

    # Passo 1: Gerar e Salvar chaves se elas não existirem
    if not os.path.exists(private_key_file) or not os.path.exists(public_key_file):
        print("Ficheiros de chave não encontrados. Gerando novo par de chaves...")
        keys = generate_keys(key_size=1024)
        
        # Salva a chave privada
        save_key_to_pem(keys['private_key'], private_key_file, is_private=True)
        # Salva a chave pública
        save_key_to_pem(keys['public_key'], public_key_file, is_private=False)
    else:
        print("Ficheiros de chave encontrados.")

    # Passo 2: Carregar as chaves dos ficheiros
    print("\nCarregando chaves dos ficheiros PEM...")
    private_key = load_key_from_pem(private_key_file)
    public_key = load_key_from_pem(public_key_file)
    print("Chaves carregadas com sucesso.")
    
    # Tenta ler a mensagem de um arquivo de exemplo
    try:
        with open("documento.txt", "r", encoding="utf-8") as file:
            original_message = file.read().strip()
        print(f"\nMensagem lida do arquivo: '{original_message}'")
    except FileNotFoundError:
        print("Erro: O arquivo 'documento.txt' não foi encontrado no diretório 'src/'.")
        return

    print("\nAssinando a mensagem com a chave privada carregada...")
    signature = sign_message(original_message.encode('utf-8'), private_key)
    print(f"Assinatura (inteiro): {signature}")

    print("\nFormatando o documento para Base64...")
    message_bytes = original_message.encode('utf-8')
    message_length_bytes = len(message_bytes).to_bytes(4, 'big')
    
    n = public_key[1]
    signature_bytes = signature.to_bytes((n.bit_length() + 7) // 8, 'big')

    signed_document = base64.b64encode(message_length_bytes + message_bytes + signature_bytes).decode('utf-8')
    print(f"Documento assinado formatado: {signed_document}")

    # Verifica o documento assinado
    print("\nVerificando a assinatura com a chave pública carregada...")
    is_valid, result = verify_signed_document(signed_document, public_key)

    if is_valid:
        print(f"\nResultado: A assinatura é VÁLIDA.")
        print(f"Mensagem recuperada: '{result}'")
    else:
        print(f"\nResultado: A assinatura é INVÁLIDA.")
        print(f"Motivo: {result}")


if __name__ == "__main__":
    main()