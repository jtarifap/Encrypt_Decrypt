import base64
import os
import customtkinter as ctk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ------------------ Lógica de Encriptación ------------------ #

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def swap_words(words: list, code: str) -> list:
    if len(code) != 4 or not code.isdigit():
        raise ValueError("El código debe ser un número de 4 dígitos.")
    pairs = [(int(code[0]), int(code[1])), (int(code[2]), int(code[3]))]
    for i, j in pairs:
        if i <= 0 or j <= 0 or i > len(words) or j > len(words):
            raise ValueError(f"Posiciones inválidas: {i}, {j}")
        i -= 1
        j -= 1
        words[i], words[j] = words[j], words[i]
    return words

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
    return base64.b64encode(salt + iv + ciphertext).decode()

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
        words = decrypted.decode().strip().split()
        words = swap_words(words, code)
        return ' '.join(words)
    except Exception:
        raise ValueError("Contraseña o código incorrecto, o datos corruptos.")

# ------------------ Interfaz Gráfica con CustomTkinter ------------------ #

def handle_encrypt():
    try:
        frase = entry_frase.get("0.0", "end").strip()
        clave = entry_clave.get()
        codigo = entry_codigo.get()
        resultado = encrypt(frase, clave, codigo)
        output.configure(state="normal")
        output.delete("0.0", "end")
        output.insert("0.0", resultado)
        output.configure(state="disabled")
    except Exception as e:
        output.configure(state="normal")
        output.delete("0.0", "end")
        output.insert("0.0", f"[Error] {e}")
        output.configure(state="disabled")


def handle_decrypt():
    try:
        frase = entry_frase.get("0.0", "end").strip()
        clave = entry_clave.get()
        codigo = entry_codigo.get()
        resultado = decrypt(frase, clave, codigo)
        output.configure(state="normal")
        output.delete("0.0", "end")
        output.insert("0.0", resultado)
        output.configure(state="disabled")
    except Exception as e:
        output.configure(state="normal")
        output.delete("0.0", "end")
        output.insert("0.0", f"[Error] {e}")
        output.configure(state="disabled")

# Configuración general
ctk.set_appearance_mode("light")  # O "dark"
ctk.set_default_color_theme("blue")  # Opciones: blue, green, dark-blue

app = ctk.CTk()
app.title("Encriptador de Frases Semilla")
app.geometry("600x600")

# Widgets
ctk.CTkLabel(app, text="Frase Semilla o Texto Encriptado:").pack(pady=(10, 0))
entry_frase = ctk.CTkTextbox(app, width=550, height=100)
entry_frase.pack(pady=(0, 10))

ctk.CTkLabel(app, text="Palabra Clave:").pack()
entry_clave = ctk.CTkEntry(app, show="*", width=300)
entry_clave.pack(pady=(0, 10))

ctk.CTkLabel(app, text="Código de 4 dígitos:").pack()
entry_codigo = ctk.CTkEntry(app, width=100)
entry_codigo.pack(pady=(0, 10))

btn_frame = ctk.CTkFrame(app)
btn_frame.pack(pady=10)
ctk.CTkButton(btn_frame, text="Encriptar", command=handle_encrypt).pack(side="left", padx=10)
ctk.CTkButton(btn_frame, text="Desencriptar", command=handle_decrypt).pack(side="right", padx=10)

ctk.CTkLabel(app, text="Resultado:").pack(pady=(10, 0))
output = ctk.CTkTextbox(app, width=550, height=120, state="disabled")
output.pack(pady=(0, 10))

# Botón Salir abajo a la derecha
exit_frame = ctk.CTkFrame(app, fg_color="transparent")
exit_frame.pack(fill="both", expand=True)

ctk.CTkButton(
    exit_frame,
    text="Salir",
    command=app.destroy,
    fg_color="#A9A9A9",        # Gris
    hover_color="#808080",     # Gris más oscuro al pasar el cursor
    text_color="black"
).pack(anchor="se", padx=25, pady=10)

app.mainloop()

