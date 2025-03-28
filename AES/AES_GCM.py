
from Crypto.Cipher import AES
import os

key = os.urandom(32) #AES-256 key
nonce = os.urandom(12) #s12bytes
def encrypt_AES_GCM(plaintext,key,nonce):
    cipher = AES.new(key,AES.MODE_GCM,nonce=nonce)
    ciphertext,tag = cipher.encrypt_and_digest(plaintext.encode())
    return ciphertext,tag

def decrypt_AES_GCM(ciphertext, tag,key,nonce):
    cipher = AES.new(key,AES.MODE_GCM,nonce=nonce)
    decrypted=cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode()


plaintext = "Hello, AES-GCM!"
ciphertext,tag = encrypt_AES_GCM(plaintext,key,nonce)
decrypted_text = decrypt_AES_GCM(ciphertext,tag,key,nonce)

print("Original:", plaintext)
print("Ciphertext (Hex):", ciphertext.hex())
print("Tag (Hex):", tag.hex())  # Auth tag ensures integrity
print("Decrypted:", decrypted_text)
