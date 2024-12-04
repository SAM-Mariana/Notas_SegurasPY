from cryptography.fernet import Fernet
import base64
import hashlib
import os

# Nombre del archivo donde se almacenan las notas
NOTES_FILE = "notas_encriptadas.txt"

# Función para generar una clave única a partir de la contraseña
def generate_key(password):
    password_bytes = password.encode()
    key = hashlib.sha256(password_bytes).digest()
    return base64.urlsafe_b64encode(key[:32])

# Función para cifrar una nota
def encrypt_note(note, password):
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted_note = fernet.encrypt(note.encode())
    return encrypted_note

# Función para descifrar una nota
def decrypt_note(encrypted_note, password):
    try:
        key = generate_key(password)
        fernet = Fernet(key)
        decrypted_note = fernet.decrypt(encrypted_note).decode()
        return decrypted_note
    except Exception:
        return None

# Función para guardar notas en el archivo
def save_notes_to_file(notes):
    with open(NOTES_FILE, "w") as file:
        for note in notes:
            file.write(note.decode() + "\n")

# Función para cargar notas del archivo
def load_notes_from_file():
    if os.path.exists(NOTES_FILE):
        with open(NOTES_FILE, "r") as file:
            return [line.strip().encode() for line in file]
    return []

# Función principal
def main():
    print("Gestor de Notas Encriptadas con Funciones Avanzadas")
    while True:
        # Menú de opciones
        print("\nOpciones:")
        print("1. Crear una nueva nota")
        print("2. Leer una nota existente")
        print("3. Editar una nota")
        print("4. Borrar una nota")
        print("5. Listar todas las notas cifradas")
        print("6. Salir")
        
        choice = input("Selecciona una opción (1/2/3/4/5/6): ")
        notes = load_notes_from_file()  # Carga las notas desde el archivo
        
        if choice == "1":
            # Crear una nueva nota
            note = input("\nEscribe tu nota: ")
            password = input("Crea una contraseña para proteger esta nota: ")
            encrypted_note = encrypt_note(note, password)
            notes.append(encrypted_note)
            save_notes_to_file(notes)
            print("\nTu nota ha sido encriptada y guardada.")
        
        elif choice == "2":
            # Leer una nota existente
            if not notes:
                print("\nNo hay notas guardadas.")
                continue

            for i, note in enumerate(notes, 1):
                print(f"{i}. {note.decode()}")

            try:
                note_number = int(input("\nSelecciona el número de la nota que quieres leer: "))
                if 1 <= note_number <= len(notes):
                    password = input("Ingresa la contraseña para desencriptar: ")
                    decrypted_note = decrypt_note(notes[note_number - 1], password)
                    if decrypted_note:
                        print("\nTu nota desencriptada es:")
                        print(decrypted_note)
                    else:
                        print("\nContraseña incorrecta o la nota está corrupta.")
                else:
                    print("\nNúmero no válido.")
            except ValueError:
                print("\nEntrada no válida.")
        
        elif choice == "3":
            # Editar una nota existente
            if not notes:
                print("\nNo hay notas guardadas.")
                continue

            for i, note in enumerate(notes, 1):
                print(f"{i}. {note.decode()}")

            try:
                note_number = int(input("\nSelecciona el número de la nota que quieres editar: "))
                if 1 <= note_number <= len(notes):
                    password = input("Ingresa la contraseña para desencriptar: ")
                    decrypted_note = decrypt_note(notes[note_number - 1], password)
                    if decrypted_note:
                        print("\nTu nota actual es:")
                        print(decrypted_note)
                        new_note = input("Escribe la nueva nota: ")
                        new_password = input("Crea una nueva contraseña para esta nota: ")
                        notes[note_number - 1] = encrypt_note(new_note, new_password)
                        save_notes_to_file(notes)
                        print("\nNota actualizada correctamente.")
                    else:
                        print("\nContraseña incorrecta o la nota está corrupta.")
                else:
                    print("\nNúmero no válido.")
            except ValueError:
                print("\nEntrada no válida.")
        
        elif choice == "4":
            # Borrar una nota
            if not notes:
                print("\nNo hay notas guardadas.")
                continue

            for i, note in enumerate(notes, 1):
                print(f"{i}. {note.decode()}")

            try:
                note_number = int(input("\nSelecciona el número de la nota que quieres borrar: "))
                if 1 <= note_number <= len(notes):
                    notes.pop(note_number - 1)
                    save_notes_to_file(notes)
                    print("\nNota eliminada correctamente.")
                else:
                    print("\nNúmero no válido.")
            except ValueError:
                print("\nEntrada no válida.")
        
        elif choice == "5":
            # Listar todas las notas cifradas
            if not notes:
                print("\nNo hay notas guardadas.")
            else:
                print("\nNotas cifradas guardadas:")
                for i, note in enumerate(notes, 1):
                    print(f"{i}. {note.decode()}")
        
        elif choice == "6":
            # Salir del programa
            print("\n¡Gracias por usar el gestor de notas!")
            break
        
        else:
            print("\nOpción no válida. Intenta nuevamente.")

# Punto de entrada del programa
if __name__ == "__main__":
    main()
