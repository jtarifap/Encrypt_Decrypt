# 🔒 encrypt_decrypt

> Herramienta de encriptación y desencriptación segura de frases semilla en Python.

---

## 📦 Instalación

```bash
# Clona el repositorio
git clone https://github.com/tjtarifap/encrypt_decrypt.git
cd encrypt_decrypt

# Instala la dependencia necesaria
pip install cryptography
```


## 🚀 Uso

```bash
python encrypt_decrypt.py
```

Al ejecutar el script, podrás elegir:

1 → Encriptar frase semilla

2 → Desencriptar frase semilla

✨ Características principales

✅ Derivación de clave segura usando PBKDF2-HMAC-SHA256.

✅ Encriptación simétrica con AES-256 en modo CFB.

✅ Reordenamiento de palabras mediante código de 4 dígitos.

✅ Sal (salt) e IV aleatorios para cada encriptación.


## 🛠️ Ejemplos de Uso

## 🔐 Encriptar
```bash
$ python encrypt_decrypt.py
¿Qué deseas hacer?
1. Encriptar frase semilla
2. Desencriptar frase semilla
Elige (1/2): 1
Introduce la frase semilla: legal winner thank year wave sausage worth useful legal winner thank yellow
Introduce tu palabra clave: MiClaveSuperSegura123
Introduce tu número de 4 dígitos (para intercambiar palabras): 1234

Frase semilla encriptada:
U2FsdGVkX1+... (cadena base64)
```

## 🔓 Desencriptar
```bash
$ python encrypt_decrypt.py
¿Qué deseas hacer?
1. Encriptar frase semilla
2. Desencriptar frase semilla
Elige (1/2): 2
Introduce la frase semilla encriptada: U2FsdGVkX1+...(cadena encriptada)
Introduce tu palabra clave: MiClaveSuperSegura123
Introduce tu número de 4 dígitos (el mismo que usaste para encriptar): 1234

Frase semilla desencriptada:
legal winner thank year wave sausage worth useful legal winner thank yellow

```

## ⚙️ ¿Cómo funciona?
Swap de palabras: Reordena la frase usando el número secreto de 4 dígitos.

Sal (Salt) y Vector de Inicialización (IV): Se generan aleatoriamente para cada operación.

Clave segura: Derivada con 100,000 iteraciones de PBKDF2 usando SHA256.

Cifrado: AES-256 en modo CFB.

## ⚠️ Advertencias
Si olvidas la contraseña o el código de 4 dígitos, NO podrás recuperar la frase semilla.

Esta herramienta es educativa. No se recomienda para proteger activos reales de criptomonedas en entornos de producción.

## 📝 Licencia
Este proyecto está licenciado bajo los términos de la Licencia MIT.

## 🤝 Contribuciones
¿Te gustaría mejorar esta herramienta?

Haz un fork

Crea una nueva branch

Envía un pull request

¡Toda ayuda es bienvenida! 🚀

## 📋 Requisitos
Python 3.7 o superior

Paquete cryptography

## 📣 Nota Final
⚡ encrypt_decrypt es un proyecto personal para aprender sobre encriptación.
Úsalo bajo tu propio riesgo.