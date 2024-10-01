import os
import base64
from cryptography.fernet import Fernet
from getpass import getpass

# Gestión de Cifrado
def generar_clave():
    # Genera y guarda una clave de cifrado
    clave = Fernet.generate_key()
    with open("clave.key", "wb") as clave_file:
        clave_file.write(clave)
    return clave

def cargar_clave():
    # Carga una clave existente desde el archivo
    return open("clave.key", "rb").read()

def cifrar_contrasena(contrasena, clave):
    # Cifra la contraseña usando la clave
    f = Fernet(clave)
    contrasena_cifrada = f.encrypt(contrasena.encode())
    return contrasena_cifrada

def descifrar_contrasena(contrasena_cifrada, clave):
    # Descifra la contraseña usando la clave
    f = Fernet(clave)
    contrasena_descifrada = f.decrypt(contrasena_cifrada).decode()
    return contrasena_descifrada

# Generación y verificación del 2FA
def generar_secreto_2fa():
    # Genera un secreto para el usuario para la autenticación 2FA
    secreto = pyotp.random_base32()
    print(f"Tu secreto de 2FA es: {secreto}")
    return secreto

def verificar_token_2fa(secreto):
    # Verifica el token 2FA proporcionado por el usuario
    totp = pyotp.TOTP(secreto)
    token = input("Introduce tu token de 2FA: ")
    return totp.verify(token)

# Programa principal
def main():
    # Gestión de contraseñas
    if not os.path.exists("clave.key"):
        clave = generar_clave()
    else:
        clave = cargar_clave()
    
    # Pregunta al usuario si quiere guardar o recuperar una contraseña
    accion = input("¿Quieres (g)uardar o (r)ecuperar una contraseña?: ").lower()

    if accion == "g":
        # Guardar una nueva contraseña
        contrasena = getpass("Introduce la contraseña que deseas guardar: ")
        contrasena_cifrada = cifrar_contrasena(contrasena, clave)
        with open("contrasenas.dat", "ab") as f:
            f.write(contrasena_cifrada + b"\n")
        print("Contraseña guardada exitosamente.")
    elif accion == "r":
        # Recuperar una contraseña
        with open("contrasenas.dat", "rb") as f:
            contrasenas = f.readlines()
        for idx, contrasena_cifrada in enumerate(contrasenas):
            print(f"{idx+1}. Contraseña {idx+1}")

        num = int(input("Introduce el número de la contraseña que quieres recuperar por favor: ")) - 1
        contrasena_cifrada = contrasenas[num].strip()
        contrasena = descifrar_contrasena(contrasena_cifrada, clave)
        print(f"La contraseña descifrada es: {contrasena}")
    
    # Proceso de 2FA
    secreto = generar_secreto_2fa()  # Genera el secreto de 2FA

    # Verificar token
    if verificar_token_2fa(secreto):
        print("Autenticación 2FA exitosa.")
    else:
        print("Autenticación 2FA fallida.")

if __name__ == "__main__":
    main()
