import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_key():
    return os.urandom(32)

def encrypt_aes(key, plaintext):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def decrypt_aes(key, ciphertext):
    backend = default_backend()
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def save_key_to_file(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()

def encrypt_rsa(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

if __name__ == "__main__":
    secret_key = generate_key()

    plaintext = "Здравствуйте, я Асмик Минасян из Технологической школы Relq.!".encode('utf-8')

    # AES Encryption/Decryption
    ciphertext = encrypt_aes(secret_key, plaintext)
    decrypted_text = decrypt_aes(secret_key, ciphertext)

    print(f"Оригинальное сообщение: {plaintext.decode('utf-8')}")
    print(f"Шифротекст: {ciphertext}")
    print(f"Дешифрованное сообщение: {decrypted_text.decode('utf-8')}")

    # RSA Encryption/Decryption
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    encrypted_message = encrypt_rsa(public_key, plaintext)
    decrypted_message = decrypt_rsa(private_key, encrypted_message)

    print(f"\nОригинальное сообщение: {plaintext.decode('utf-8')}")
    print(f"Зашифрованное сообщение: {encrypted_message}")
    print(f"Дешифрованное сообщение: {decrypted_message.decode('utf-8')}")

