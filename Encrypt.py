Python 3.11.5 (tags/v3.11.5:cce6ba9, Aug 24 2023, 14:38:34) [MSC v.1936 64 bit (AMD64)] on win32
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Test in IDLE
print(caesar_encrypt("HELLO", 3))   # KHOOR
print(caesar_decrypt("KHOOR", 3))   # HELLO


def xor_encrypt(text, key):
    return ''.join(chr(ord(c) ^ key) for c in text)

def xor_decrypt(cipher, key):
    return xor_encrypt(cipher, key)  # XOR is symmetric

# Test
encrypted = xor_encrypt("HELLO", 5)
print("Encrypted:", encrypted)
print("Decrypted:", xor_decrypt(encrypted, 5))

print("Choose an option:")
print("1. Caesar Cipher")
print("2. XOR Cipher")
choice = input("Enter choice: ")

if choice == "1":
    mode = input("Encrypt or Decrypt (e/d)? ")
    text = input("Enter text: ")
    shift = int(input("Enter shift value: "))
    if mode == "e":
        print("Encrypted:", caesar_encrypt(text, shift))
    else:
        print("Decrypted:", caesar_decrypt(text, shift))

elif choice == "2":
    mode = input("Encrypt or Decrypt (e/d)? ")
    text = input("Enter text: ")
    key = int(input("Enter XOR key (integer): "))
    if mode == "e":
        print("Encrypted:", xor_encrypt(text, key))
    else:
        print("Decrypted:", xor_decrypt(text, key))

