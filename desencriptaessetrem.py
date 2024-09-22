import base64
import nacl.secret
import nacl.utils
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
from nacl.exceptions import CryptoError
import sys

# Script desenvolvido por 0xluiz - https://github.com/0xluiz

def desencriptar_arquivo(caminho_arquivo_chave, string_base64):
    # Lê o arquivo de chave como binário
    with open(caminho_arquivo_chave, 'rb') as arquivo_chave:
        chave = arquivo_chave.read()

    # Decodifica a string em base64
    string_decodificada = base64.b64decode(string_base64)

    # Define o tamanho do nonce com base no algoritmo XChaCha20-Poly1305
    tamanho_nonce = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

    # Extrai o nonce e o ciphertext da string decodificada
    nonce = string_decodificada[:tamanho_nonce]
    cifra = string_decodificada[tamanho_nonce:]

    # Descriptografa o ciphertext
    try:
        texto_plano = crypto_aead_xchacha20poly1305_ietf_decrypt(
            cifra, nonce, nonce, chave
        )
        return texto_plano.decode()
    except CryptoError:
        return "Falha na descriptografia!"

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python desencriptaessetrem.py <caminho_arquivo_chave> <string_base64>")
        sys.exit(1)

    caminho_arquivo_chave = sys.argv[1]
    string_base64 = sys.argv[2]

    # Chama a função de desencriptação
    resultado = desencriptar_arquivo(caminho_arquivo_chave, string_base64)
    print("Senha:", resultado)
