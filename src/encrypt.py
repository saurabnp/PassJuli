import os,base64
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2 

def get_key(masterpassword, salt):
    return PBKDF2(masterpassword, salt, dkLen=32, count=100000)

# Encrypt function
def encrypt(masterpassword, passwordToEncrypt):
    salt = os.urandom(16)
    key = get_key(masterpassword, salt)
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(passwordToEncrypt.encode("utf-8"))
    return base64.b64encode(salt + iv + tag + ciphertext).decode("utf-8")

# Decrypt function
def decrypt(masterpassword, encryptedPassword):
    passwordToDecrypt = base64.b64decode(encryptedPassword)
    salt, iv, tag, ciphertext = passwordToDecrypt[:16], passwordToDecrypt[16:28], passwordToDecrypt[28:44], passwordToDecrypt[44:]
    key = get_key(masterpassword, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")