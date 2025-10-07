# Gerador e Verificador de Assinaturas RSA

Este projeto é uma ferramenta de linha de comando (CLI) implementada em Python para gerar pares de chaves RSA, assinar digitalmente ficheiros e verificar assinaturas, utilizando o padrão de preenchimento OAEP para maior segurança.

## Funcionalidades

* **Geração de Chaves:** Cria pares de chaves RSA (pública e privada) com tamanho personalizável e salva-os em formato PEM.
* **Assinatura de Ficheiros:** Assina qualquer ficheiro usando uma chave privada, gerando um ficheiro de saída com a assinatura embutida e codificada em Base64.
* **Verificação de Assinaturas:** Verifica a integridade e autenticidade de um ficheiro assinado usando a chave pública correspondente.

## Pré-requisitos

* Python 3.x

## Instalação

1.  Clone o repositório para a sua máquina local:
    ```bash
    git clone [https://github.com/viniciustome61/gerador-assinaturas-rsa.git](https://github.com/viniciustome61/gerador-assinaturas-rsa.git)
    ```

2.  Navegue para o diretório do projeto:
    ```bash
    cd gerador-assinaturas-rsa
    ```

3.  Instale as dependências necessárias (a biblioteca `pycryptodome`):
    ```bash
    pip install -r requirements.txt
    ```
    *(Nota: Teremos de criar o ficheiro requirements.txt)*

## Como Usar

Todas as operações são executadas a partir do terminal, dentro da pasta `codigo fonte`.

### 1. Gerar um Par de Chaves

Execute o seguinte comando para criar os ficheiros `chave_privada.pem` e `chave_publica.pem`:

```bash
python geradorVerificador.py gerar-chaves


