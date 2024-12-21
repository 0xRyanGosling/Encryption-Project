import tkinter as tk
from tkinter import scrolledtext, Text

# Define the base64 encoding characters
base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def base64_encode(plaintext):
    """
    Encodes the plaintext using base64 encoding.
    """
    encoded_chars = []  # List to store encoded characters
    padding = ""  # Padding characters for base64 encoding
    
    # Convert each three bytes to four base64 characters
    for i in range(0, len(plaintext), 3):
        chunk = plaintext[i:i+3]  # Get chunk of three characters
        # Convert chunk to binary representation
        binary_chunk = ''.join(format(ord(char), '08b') for char in chunk)
        # '08b' is used in Python to format an integer as an 8-bit binary string
        
        # Pad binary_chunk if its length is less than 24 bits
        binary_chunk += '0' * (24 - len(binary_chunk))
        
        # Convert binary_chunk to base64 characters
        encoded_chars.extend([base64_chars[int(binary_chunk[j:j+6], 2)] for j in range(0, 24, 6)])
        
        # Add padding '=' if necessary
        padding += '=' * (3 - len(chunk))
    
    return ''.join(encoded_chars) + padding  # Concatenate encoded characters with padding

def base64_decode(encoded_text):
    """
    Decodes the base64 encoded text.
    """
    decoded_chars = []  # List to store decoded characters
    
    # Remove padding '=' characters
    encoded_text = encoded_text.rstrip('=')
    
    # Convert each four base64 characters to three bytes
    for i in range(0, len(encoded_text), 4):
        chunk = encoded_text[i:i+4]  # Get chunk of four characters
        # Convert chunk to binary representation
        binary_chunk = ''.join(format(base64_chars.index(char), '06b') for char in chunk)
        
        # Convert binary_chunk to characters
        #2 for base 2 (Binary)
        decoded_chars.extend([chr(int(binary_chunk[j:j+8], 2)) for j in range(0, 24, 8)])
    
    return ''.join(decoded_chars)  # Concatenate decoded characters

def encode_text():
    plaintext = input_text.get("1.0", "end-1c")  # Get plaintext from input text area
    if cipher_var.get() == 0:  # Base64 encoding
        encoded_text = base64_encode(plaintext)  # Encode plaintext using base64
    elif cipher_var.get() == 1:  # Monoalphabetic cipher
        encoded_text = monoalphabetic_encrypt(plaintext, monoalphabetic_key)
    else:  # Vigenère cipher
        key = key_entry.get()
        if key:
            encoded_text = vigenere_encrypt(plaintext, key)
        else:
            encoded_text = "Error: Please enter a key for encryption"
    output_text.delete(1.0, tk.END)  # Clear output text area
    output_text.insert(tk.END, "Encoded Text: " + encoded_text)  # Display encoded text

def decode_text():
    encoded_text = input_text.get("1.0", "end-1c")  # Get encoded text from input text area no extra lines
    if cipher_var.get() == 0:  # Base64 decoding
        decoded_text = base64_decode(encoded_text)  # Decode encoded text using base64
    elif cipher_var.get() == 1:  # Monoalphabetic cipher
        decoded_text = monoalphabetic_decrypt(encoded_text, monoalphabetic_key)
    else:  # Vigenère cipher
        key = key_entry.get()
        if key:
            decoded_text = vigenere_decrypt(encoded_text, key)
        else:
            decoded_text = "Error: Please enter a key for decryption"
    output_text.delete(1.0, tk.END)  # Clear output text area
    output_text.insert(tk.END, "Decoded Text: " + decoded_text)  # Display decoded text

# Define the alphabet
alphabet = "abcdefghijklmnopqrstuvwxyz"

# Fixed key for the monoalphabetic cipher
monoalphabetic_key = "qwertyuiopasdfghjklzxcvbnm"

def monoalphabetic_encrypt(plaintext, key):
    """
    Encrypts the plaintext using the monoalphabetic cipher with the given key.
    """
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            # Map the plaintext character to the corresponding key character
            index = alphabet.index(char.lower())
            if char.isupper():
                ciphertext += key[index].upper()
            else:
                ciphertext += key[index]
        else:
            # Leave non-alphabetic characters unchanged
            ciphertext += char
    return ciphertext

def monoalphabetic_decrypt(ciphertext, key):
    """
    Decrypts the ciphertext using the monoalphabetic cipher with the given key.
    """
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            # Map the ciphertext character to the corresponding plaintext character
            index = key.index(char.lower())
            if char.isupper():
                plaintext += alphabet[index].upper()
            else:
                plaintext += alphabet[index]
        else:
            # Leave non-alphabetic characters unchanged
            plaintext += char
    return plaintext

def vigenere_encrypt(plaintext, key):
    """
    Encrypts the plaintext using the Vigenère cipher with the given key.
    """
    ciphertext = ""
    if not key:
        return "Error: Please enter a key for encryption"
    
    key_length = len(key)
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = alphabet.index(key[i % key_length].lower())
            if char.isupper():
                ciphertext += chr((ord(char) - ord('A') + shift) % 26 + ord('A')) #cause of start from 0 
                
            else:
                ciphertext += chr((ord(char) - ord('a') + shift) % 26 + ord('a')) #the same but for small
        else:
            ciphertext += char
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    """
    Decrypts the ciphertext using the Vigenère cipher with the given key.
    """
    plaintext = ""
    if not key:
        return "Error: Please enter a key for decryption"
    
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = alphabet.index(key[i % key_length].lower())
            if char.isupper():
                plaintext += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                plaintext += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
        else:
            plaintext += char
    return plaintext

def encrypt_text():
    plaintext = input_text.get("1.0", "end-1c")
    if cipher_var.get() == 0:  # Base64 encoding
        encoded_text = base64_encode(plaintext)
    elif cipher_var.get() == 1:  # Monoalphabetic cipher
        encoded_text = monoalphabetic_encrypt(plaintext, monoalphabetic_key)
    else:  # Vigenère cipher
        key = key_entry.get()
        if key:
            encoded_text = vigenere_encrypt(plaintext, key)
        else:
            encoded_text = "Error: Please enter a key for encryption"
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Ciphertext: " + encoded_text)

def decrypt_text():
    ciphertext = input_text.get("1.0", "end-1c")
    if cipher_var.get() == 0:  # Base64 decoding
        decoded_text = base64_decode(ciphertext)
    elif cipher_var.get() == 1:  # Monoalphabetic cipher
        decoded_text = monoalphabetic_decrypt(ciphertext, monoalphabetic_key)
    else:  # Vigenère cipher
        key = key_entry.get()
        if key:
            decoded_text = vigenere_decrypt(ciphertext, key)
        else:
            decoded_text = "Error: Please enter a key for decryption"
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Plaintext: " + decoded_text)

# Create GUI window
root = tk.Tk()
root.title("Eagles Team")

# Set dark theme
root.configure(bg="#2b2b2b")
root.option_add("*TCombobox*Listbox*Background", "#2b2b2b")
root.option_add("*TCombobox*Listbox*Foreground", "white")
root.option_add("*TCombobox*Listbox*selectBackground", "#3a3a3a")
root.option_add("*TCombobox*Listbox*selectForeground", "white")

# Cipher Selection Radio Button
cipher_var = tk.IntVar()
base64_radio = tk.Radiobutton(root, text="Base64", variable=cipher_var, value=0, bg="#2b2b2b", fg="white", selectcolor="#2b2b2b")
base64_radio.grid(row=0, column=0, padx=10, pady=5)
monoalphabetic_radio = tk.Radiobutton(root, text="Monoalphabetic Cipher", variable=cipher_var, value=1, bg="#2b2b2b", fg="white", selectcolor="#2b2b2b")
monoalphabetic_radio.grid(row=0, column=1, padx=10, pady=5)
vigenere_radio = tk.Radiobutton(root, text="Vigenère Cipher", variable=cipher_var, value=2, bg="#2b2b2b", fg="white", selectcolor="#2b2b2b")
vigenere_radio.grid(row=0, column=2, padx=10, pady=5)
cipher_var.set(0)  # Set default value to Base64

# Input Text Area
input_text = scrolledtext.ScrolledText(root, width=50, height=10, wrap=tk.WORD, bg="#1e1e1e", fg="white")
input_text.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

# Key Label and Entry for Vigenère Cipher
key_label = tk.Label(root, text="Key:", bg="#2b2b2b", fg="white")
key_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
key_entry = tk.Entry(root, bg="#1e1e1e", fg="white", insertbackground="white")
key_entry.grid(row=2, column=1, padx=10, pady=5)

# Encrypt and Decrypt Buttons
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text, bg="#333333", fg="white")
encrypt_button.grid(row=3, column=1, padx=10, pady=5)
decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text, bg="#333333", fg="white")
decrypt_button.grid(row=3, column=2, padx=10, pady=5)

# Output Text Area
output_text = Text(root, width=50, height=1, bg="#1e1e1e", fg="white")
output_text.grid(row=4, column=0, columnspan=3, padx=10, pady=5)

root.mainloop()

#the end of code
