import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Función para derivar clave desde la palabra clave
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Función para hacer swaps según el número
def swap_words(words: list, code: str) -> list:
    if len(code) != 4 or not code.isdigit():
        raise ValueError("El código debe ser un número de 4 dígitos.")
    
    # Hacemos swaps por pares
    pairs = [(int(code[0]), int(code[1])), (int(code[2]), int(code[3]))]

    for i, j in pairs:
        if i <= 0 or j <= 0 or i > len(words) or j > len(words):
            raise ValueError(f"Posiciones inválidas: {i}, {j}")

        # Ajustar de 1-based a 0-based
        i -= 1
        j -= 1
        words[i], words[j] = words[j], words[i]
    
    return words

# Función para encriptar
def encrypt(seed_phrase: str, password: str, code: str) -> str:
    words = seed_phrase.strip().split()
    words = swap_words(words, code)
    modified_phrase = ' '.join(words)

    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(modified_phrase.encode()) + encryptor.finalize()

    encrypted_data = base64.b64encode(salt + iv + ciphertext).decode()
    return encrypted_data

# Función para desencriptar
def decrypt(encrypted_data: str, password: str, code: str) -> str:
    data = base64.b64decode(encrypted_data)
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        modified_phrase = decrypted.decode()
        words = modified_phrase.strip().split()

        # Para deshacer el swap, aplicamos el mismo swap de nuevo
        words = swap_words(words, code)
        original_phrase = ' '.join(words)

        return original_phrase
    except Exception:
        raise ValueError("Contraseña o código incorrecto, o datos corruptos.")

# Programa principal
if __name__ == "__main__":
    print("¿Qué deseas hacer?")
    print("1. Encriptar frase semilla")
    print("2. Desencriptar frase semilla")
    choice = input("Elige (1/2): ")

    if choice == '1':
        seed_phrase = input("Introduce la frase semilla: ")
        password = input("Introduce tu palabra clave: ")
        code = input("Introduce tu número de 4 dígitos (para intercambiar palabras): ")
        encrypted = encrypt(seed_phrase, password, code)
        print("\nFrase semilla encriptada:")
        print(encrypted)

    elif choice == '2':
        encrypted_data = input("Introduce la frase semilla encriptada: ")
        password = input("Introduce tu palabra clave: ")
        code = input("Introduce tu número de 4 dígitos (el mismo que usaste para encriptar): ")
        try:
            decrypted = decrypt(encrypted_data, password, code)
            print("\nFrase semilla desencriptada:")
            print(decrypted)
        except ValueError as e:
            print("\nError:", e)

    else:
        print("Opción no válida.")
