from cryptography.fernet import Fernet  # Biblioteca para cifrado simétrico
import base64  # Biblioteca para codificar y decodificar datos en Base64
import hashlib  # Biblioteca para generar hashes (en este caso, SHA256)

# Función para generar una clave única a partir de una contraseña
def generate_key(password):
    # Convierte la contraseña en bytes
    password_bytes = password.encode()
    # Genera un hash SHA256 a partir de la contraseña
    key = hashlib.sha256(password_bytes).digest()
    # Convierte los primeros 32 bytes del hash en una clave segura codificada en Base64
    return base64.urlsafe_b64encode(key[:32])

# Función para cifrar una nota usando una contraseña
def encrypt_note(note, password):
    key = generate_key(password)  # Genera una clave única basada en la contraseña
    fernet = Fernet(key)  # Crea un objeto Fernet con la clave
    encrypted_note = fernet.encrypt(note.encode())  # Cifra la nota convertida a bytes
    return encrypted_note  # Devuelve la nota cifrada

# Función para descifrar una nota usando una contraseña
def decrypt_note(encrypted_note, password):
    try:
        key = generate_key(password)  # Genera una clave única basada en la contraseña
        fernet = Fernet(key)  # Crea un objeto Fernet con la clave
        decrypted_note = fernet.decrypt(encrypted_note).decode()  # Descifra la nota y la convierte en texto
        return decrypted_note  # Devuelve la nota descifrada
    except Exception:  # Si ocurre un error (por ejemplo, contraseña incorrecta o datos corruptos)
        return None  # Devuelve None

# Función principal que controla el flujo del programa
def main():
    print("Gestor de Notas Encriptadas")  # Muestra el título del programa
    while True:  # Bucle principal del programa
        # Muestra las opciones disponibles para el usuario
        print("\nOpciones:")
        print("1. Crear una nueva nota")
        print("2. Leer una nota existente")
        print("3. Salir")
        
        # Solicita al usuario que seleccione una opción
        choice = input("Selecciona una opción (1/2/3): ")
        
        if choice == "1":  # Opción para crear una nueva nota
            note = input("\nEscribe tu nota: ")  # Solicita la nota al usuario
            password = input("Crea una contraseña para proteger esta nota: ")  # Solicita la contraseña
            encrypted_note = encrypt_note(note, password)  # Cifra la nota con la contraseña
            print("\nTu nota ha sido encriptada:")  # Muestra la nota cifrada
            print(encrypted_note.decode())  # Imprime la nota cifrada en texto legible
            
        elif choice == "2":  # Opción para leer una nota existente
            # Solicita al usuario que pegue la nota cifrada
            encrypted_note_input = input("\nPega aquí la nota encriptada: ").encode()
            password = input("Ingresa la contraseña para desencriptar: ")  # Solicita la contraseña
            decrypted_note = decrypt_note(encrypted_note_input, password)  # Intenta descifrar la nota
            if decrypted_note:  # Si la descifra correctamente
                print("\nTu nota desencriptada es:")  # Muestra la nota descifrada
                print(decrypted_note)
            else:  # Si la contraseña es incorrecta o la nota está corrupta
                print("\nContraseña incorrecta o la nota está corrupta.")
        
        elif choice == "3":  # Opción para salir del programa
            print("\n¡Gracias por usar el gestor de notas!")  # Mensaje de despedida
            break  # Termina el programa
        
        else:  # Si la opción seleccionada no es válida
            print("\nOpción no válida. Intenta nuevamente.")

# Punto de entrada del programa
if __name__ == "__main__":
    main()  # Llama a la función principal para iniciar el programa


# ¿Cómo funciona?
# 1.Crear una nueva nota:
# Escribe una nota y define una contraseña.
# La nota será cifrada utilizando la contraseña como clave.

# 2.Leer una nota existente:
# Pega la nota cifrada y proporciona la contraseña correcta.
# Si la contraseña es válida, la nota será descifrada; si no, mostrará un mensaje de error.

# 3.Salir:
# Finaliza el programa.