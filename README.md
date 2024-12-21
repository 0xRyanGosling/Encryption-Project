# Encryption-Project
This is a small encryption and decryption project that use base64, monoalphabetic, and vinegar


# Cipher GUI Application

This project is a graphical user interface (GUI) application that provides encryption and decryption functionalities using Base64, Monoalphabetic Cipher, and Vigenère Cipher. The application is implemented in Python with the help of the Tkinter library.

## Features

- **Base64 Encoding/Decoding:** Converts plaintext to Base64-encoded text and vice versa.
- **Monoalphabetic Cipher:** Encrypts and decrypts text using a fixed substitution cipher.
- **Vigenère Cipher:** Supports encryption and decryption with a user-defined key.
- **Dark Themed GUI:** A visually appealing dark mode interface.
- **Scrolled Text Input/Output:** Allows users to input and display large blocks of text with ease.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/0xRyanGosling/Encryption-Project
   cd Encryption-Project
   ```
2. Ensure you have Python installed (version 3.6 or higher).
3. Install dependencies (if any, like `tkinter`, though it is included by default in most Python installations).

## How to Use

1. Run the application:
   ```bash
   python cipher_gui.py
   ```
2. Select the cipher type using the radio buttons:
   - **Base64** for Base64 encoding/decoding.
   - **Monoalphabetic Cipher** for fixed substitution encryption/decryption.
   - **Vigenère Cipher** for key-based encryption/decryption.
3. Enter your text in the input area.
4. (Optional) If using Vigenère Cipher, provide a key in the designated input field.
5. Click on "Encrypt" or "Decrypt" to perform the desired operation.
6. View the result in the output area.

## Code Highlights

- **Base64 Encoding/Decoding:**
  ```python
  def base64_encode(plaintext):
      # Implementation details here...
  
  def base64_decode(encoded_text):
      # Implementation details here...
  ```

- **Monoalphabetic Cipher Encryption/Decryption:**
  ```python
  def monoalphabetic_encrypt(plaintext, key):
      # Implementation details here...
  
  def monoalphabetic_decrypt(ciphertext, key):
      # Implementation details here...
  ```

- **Vigenère Cipher Encryption/Decryption:**
  ```python
  def vigenere_encrypt(plaintext, key):
      # Implementation details here...
  
  def vigenere_decrypt(ciphertext, key):
      # Implementation details here...
  ```

- **Dark Theme:**
  ```python
  root.configure(bg="#2b2b2b")
  ```

## Contributions

Feel free to fork the repository and submit a pull request to improve the application or add new features.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

Enjoy encrypting and decrypting with this intuitive GUI application!

