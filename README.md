<h1 align="center">Encryption-Decryption-Tool</h1>

<br>

![image016](https://github.com/Hasul79/Encryption-Decryption-Tool/assets/95657084/e4d7961c-3ff6-4e35-985a-0e7b03f791e8)


<ul>
 
<li> Чтобы выполнить этот код, вам необходимо установить библиотеку cryptography.</li>

<br/>

![Screenshot 2024-03-02 215243](https://github.com/Hasul79/Encryption-Decryption-Tool/assets/95657084/6916c188-f9d0-4b56-82d0-a331dac86dc8)

 <li>Создайте скрипт на Python:</li>
 
<br/>

![Screenshot 2024-03-02 021427](https://github.com/Hasul79/Encryption-Decryption-Tool/assets/95657084/aa764be2-bfaa-4828-9e5e-8347f41a3d83)


<li>Откройте свой любимый текстовый редактор,вставьте код</li>


```
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


```
<br/>

<li>Запустите скрипт</li>


![Screenshot 2024-03-02 215304](https://github.com/Hasul79/Encryption-Decryption-Tool/assets/95657084/d505752a-ed77-4f11-baed-88182b42bf6c)

</ul>

# Объяснение:

<h1>Данный скрипт на Python реализует пример шифрования и дешифрования с использованием алгоритмов AES и RSA.</h1>

<ol>

<li>Генерация ключа:</li>


 ![Screenshot 2024-03-02 222837](https://github.com/Hasul79/Encryption-Decryption-Tool/assets/95657084/68584dbb-931a-4c9e-8fd8-98e6f89abbf6)


<p>Функция generate_key создает случайный ключ длиной 32 байта (256 бит) с использованием os.urandom().</p>

<br/>

<li>Шифрование и дешифрование AES:</li>

![Screenshot 2024-03-02 223031](https://github.com/Hasul79/Encryption-Decryption-Tool/assets/95657084/9aeb172a-1ce7-4d1c-8332-fe08719e7f52)


<b>Функции encrypt_aes и decrypt_aes выполняют шифрование и дешифрование текста с использованием алгоритма AES в режиме CFB (Cipher Feedback). Результаты выводятся на экран.</b>

<br/>

<li>Сохранение и загрузка ключа в файл:</li>

![Screenshot 2024-03-02 223236](https://github.com/Hasul79/Encryption-Decryption-Tool/assets/95657084/d340fb8a-1697-4d50-8ed5-4813afafa27e)


<p>Функции save_key_to_file и load_key_from_file сохраняют и загружают ключ в/из файла.</p>

<br/>

<li>Шифрование и дешифрование RSA:</li>

![Screenshot 2024-03-02 223626](https://github.com/Hasul79/Encryption-Decryption-Tool/assets/95657084/5789040d-c4fb-451a-acc2-5b9a78b69776)

<p>Генерируется пара RSA-ключей (закрытый и открытый), затем выполняется шифрование и дешифрование текста с использованием RSA. </p>

<br/>

<li>Вывод результатов на экран:</li>



![Screenshot 2024-03-02 223859](https://github.com/Hasul79/Encryption-Decryption-Tool/assets/95657084/a97254ba-ca6b-4fc7-aed6-1af77ef7fac9)

<p>Здесь выводятся результаты работы алгоритмов AES и RSA на экран. Оригинальное сообщение, шифротекст и дешифрованное сообщение.</p>

</ol>


#Author: Hasmik Minasyan 02.03.2024


