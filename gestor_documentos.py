from cryptography.fernet import Fernet  # Biblioteca para cifrado simétrico
import base64  # Biblioteca para codificar y decodificar datos en Base64
import hashlib  # Biblioteca para generar hashes (SHA256 en este caso)
import os  # Biblioteca para interactuar con el sistema operativo


# Función para generar una clave a partir de la contraseña
def generate_key(password):
    # Convierte la contraseña en bytes
    password_bytes = password.encode()
    # Crea un hash SHA-256 de la contraseña y utiliza los primeros 32 bytes para la clave
    key = hashlib.sha256(password_bytes).digest()
    # Convierte la clave a un formato seguro para URL
    return base64.urlsafe_b64encode(key[:32])

# Función para cifrar una nota con una contraseña
def encrypt_note(note, password):
    # Genera una clave basada en la contraseña
    key = generate_key(password)
    # Crea un objeto Fernet con la clave generada
    fernet = Fernet(key)
    # Cifra la nota
    encrypted_note = fernet.encrypt(note.encode())
    return encrypted_note

# Función para descifrar una nota con una contraseña
def decrypt_note(encrypted_note, password):
    try:
        # Genera la clave basada en la contraseña
        key = generate_key(password)
        # Crea un objeto Fernet con la clave generada
        fernet = Fernet(key)
        # Descifra la nota
        decrypted_note = fernet.decrypt(encrypted_note).decode()
        return decrypted_note
    except Exception:
        # Si hay un error (clave incorrecta o dato corrupto), retorna None
        return None

# Función para guardar notas en un archivo
def save_to_file(file_name, encrypted_note):
    # Abre el archivo en modo "append binary" para agregar datos sin borrar los existentes
    with open(file_name, "ab") as file:
        # Escribe la nota cifrada en una nueva línea
        file.write(encrypted_note + b"\n")

# Función para leer todas las notas cifradas de un archivo
def read_from_file(file_name):
    # Verifica si el archivo existe; si no, retorna una lista vacía
    if not os.path.exists(file_name):
        return []
    # Abre el archivo en modo "read binary" para leer las notas cifradas
    with open(file_name, "rb") as file:
        return file.readlines()

# Función principal
def main():
    # Nombre del archivo donde se almacenarán las notas cifradas
    file_name = "notas_encriptadas.txt"
    print("Gestor de Notas Encriptadas con Documento")
    while True:
        # Menú de opciones
        print("\nOpciones:")
        print("1. Crear una nueva nota")
        print("2. Leer todas las notas")
        print("3. Salir")
        
        # Solicita al usuario que seleccione una opción
        choice = input("Selecciona una opción (1/2/3): ")
        
        if choice == "1":
            # Opción para crear una nueva nota
            note = input("\nEscribe tu nota: ")
            password = input("Crea una contraseña para proteger esta nota: ")
            # Cifra la nota con la contraseña proporcionada
            encrypted_note = encrypt_note(note, password)
            # Guarda la nota cifrada en el archivo
            save_to_file(file_name, encrypted_note)
            print("\nTu nota ha sido encriptada y guardada.")
        
        elif choice == "2":
            # Opción para leer notas existentes
            encrypted_notes = read_from_file(file_name)
            if not encrypted_notes:
                print("\nNo hay notas guardadas.")
                continue

            # Muestra las notas cifradas almacenadas en el archivo
            print("\nNotas encontradas:")
            for i, encrypted_note in enumerate(encrypted_notes, 1):
                print(f"{i}. {encrypted_note.decode().strip()}")

            try:
                # Solicita al usuario seleccionar una nota
                note_number = int(input("\nSelecciona el número de la nota que quieres leer: "))
                if 1 <= note_number <= len(encrypted_notes):
                    # Solicita la contraseña para descifrar la nota
                    password = input("Ingresa la contraseña para desencriptar: ")
                    decrypted_note = decrypt_note(encrypted_notes[note_number - 1].strip(), password)
                    if decrypted_note:
                        print("\nTu nota desencriptada es:")
                        print(decrypted_note)
                    else:
                        print("\nContraseña incorrecta o la nota está corrupta.")
                else:
                    print("\nNúmero de nota no válido.")
            except ValueError:
                print("\nEntrada no válida.")
        
        elif choice == "3":
            # Opción para salir del programa
            print("\n¡Gracias por usar el gestor de notas!")
            break
        else:
            # Manejo de opción no válida
            print("\nOpción no válida. Intenta nuevamente.")

# Punto de entrada del programa
if __name__ == "__main__":
    main()


# ¿Qué hace este código?
# 1.Guardar notas en un archivo
# Cada nota cifrada se guarda en un archivo llamado notas_encriptadas.txt
# Si el archivo no existe, se crea automáticamente.

# 2.Leer notas desde el archivo
# Muestra todas las notas cifradas almacenadas en el archivo.
# Permite seleccionar una nota específica por su número para intentar descifrarla con una contraseña.

# 3.Gestión de contraseñas
# Cada nota tiene su propia contraseña. Solo podrás descifrarla si ingresas la contraseña correcta.