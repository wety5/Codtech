import os
import argparse
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# --- Configuration Constants ---
AES_KEY_BITS = 256
AES_KEY_BYTES = AES_KEY_BITS // 8 # 32 bytes for AES-256
GCM_IV_BYTES = 12 # Recommended IV size for AES-GCM
PBKDF2_SALT_BYTES = 16
PBKDF2_ITERATIONS = 200000 # Number of iterations for PBKDF2 (should be high for security)
PBKDF2_HASH_ALGO = hashes.SHA256()

# --- Utility Functions ---

def _print_info(message):
    """Prints an informational message."""
    print(f"[INFO] {message}")

def _print_success(message):
    """Prints a success message."""
    print(f"[SUCCESS] {message}")

def _print_error(message):
    """Prints an error message."""
    print(f"[ERROR] {message}")

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derives an AES-256 key from a passphrase using PBKDF2.

    Args:
        passphrase (str): The user's passphrase.
        salt (bytes): A cryptographically strong random salt.

    Returns:
        bytes: The derived 32-byte AES key.
    """
    kdf = PBKDF2HMAC(
        algorithm=PBKDF2_HASH_ALGO,
        length=AES_KEY_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    # Encode passphrase to bytes for KDF
    key = kdf.derive(passphrase.encode('utf-8'))
    return key

def encrypt_file(input_filepath: str, output_filepath: str, passphrase: str):
    """
    Encrypts a file using AES-256-GCM with a PBKDF2-derived key.

    The output file will contain the salt, IV, and then the encrypted data
    (which includes the GCM authentication tag).

    Args:
        input_filepath (str): Path to the file to be encrypted.
        output_filepath (str): Path where the encrypted file will be saved.
        passphrase (str): The passphrase used for key derivation.
    """
    if not os.path.exists(input_filepath):
        _print_error(f"Input file not found: {input_filepath}")
        return

    _print_info(f"Encrypting '{input_filepath}'...")

    try:
        # Generate random salt and IV
        salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
        iv = secrets.token_bytes(GCM_IV_BYTES)

        # Derive the key from the passphrase and salt
        key = derive_key(passphrase, salt)

        # Create AES-GCM cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Read the entire input file content
        with open(input_filepath, 'rb') as f_in:
            plaintext = f_in.read()

        # Encrypt the plaintext
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag # Get the authentication tag from GCM

        # Concatenate salt, IV, ciphertext, and tag for storage
        # The 'tag' is implicitly part of the 'ciphertext' returned by GCM in many libraries,
        # but here we explicitly retrieve it to ensure clarity in concatenation if needed.
        # However, for cryptography.io, `ciphertext` includes the tag if `encryptor.update`
        # and `encryptor.finalize` are used. Let's combine them logically.
        # The documentation for GCM shows the tag is separate:
        # result = encryptor.update(data) + encryptor.finalize()
        # tag = encryptor.tag
        # The combined format will be: salt || iv || ciphertext || tag

        # Combine salt, IV, ciphertext, and tag for the output file
        # The cryptography library's `encryptor.update` and `encryptor.finalize` return
        # the ciphertext, and `encryptor.tag` returns the authentication tag.
        # The convention is usually salt || iv || ciphertext || tag
        combined_data = salt + iv + ciphertext + tag

        # Write the combined data to the output file
        with open(output_filepath, 'wb') as f_out:
            f_out.write(combined_data)

        _print_success(f"File encrypted successfully: '{output_filepath}'")

    except Exception as e:
        _print_error(f"Encryption failed: {e}")

def decrypt_file(input_filepath: str, output_filepath: str, passphrase: str):
    """
    Decrypts an encrypted file using AES-256-GCM with a PBKDF2-derived key.

    Expects the input file to be in the format: salt || IV || ciphertext || tag.

    Args:
        input_filepath (str): Path to the encrypted file.
        output_filepath (str): Path where the decrypted file will be saved.
        passphrase (str): The passphrase used for key derivation.
    """
    if not os.path.exists(input_filepath):
        _print_error(f"Input encrypted file not found: {input_filepath}")
        return

    _print_info(f"Decrypting '{input_filepath}'...")

    try:
        # Read the combined encrypted data
        with open(input_filepath, 'rb') as f_in:
            combined_data = f_in.read()

        # Ensure the file is large enough to contain salt, IV, and at least some data+tag
        min_length = PBKDF2_SALT_BYTES + GCM_IV_BYTES + 16 # 16 bytes for GCM tag
        if len(combined_data) < min_length:
            raise ValueError("Invalid encrypted file format: File too short.")

        # Extract salt, IV, ciphertext, and tag
        salt = combined_data[0:PBKDF2_SALT_BYTES]
        iv = combined_data[PBKDF2_SALT_BYTES : PBKDF2_SALT_BYTES + GCM_IV_BYTES]
        ciphertext_and_tag = combined_data[PBKDF2_SALT_BYTES + GCM_IV_BYTES :]

        # The last 16 bytes of the `ciphertext_and_tag` are the authentication tag for GCM
        # For decryption, the `modes.GCM` expects the full ciphertext (including potential padding from finalize),
        # and the tag is passed separately to the decryptor.authenticate_tag() method.
        # However, cryptography.io's GCM mode expects the tag at the end of the ciphertext bytes
        # passed to `decryptor.update` or `decryptor.finalize`.
        # Let's verify the correct slicing for `modes.GCM`.
        # Correct: ciphertext is the data, and the tag is passed to decryptor.authenticate_tag(tag).
        
        # Split ciphertext and tag
        ciphertext = ciphertext_and_tag[:-16] # Assuming 16-byte GCM tag
        tag = ciphertext_and_tag[-16:]

        # Derive the key using the extracted salt
        key = derive_key(passphrase, salt)

        # Create AES-GCM cipher for decryption
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        # The `decryptor.finalize()` will automatically check the authentication tag
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Write the decrypted plaintext to the output file
        with open(output_filepath, 'wb') as f_out:
            f_out.write(plaintext)

        _print_success(f"File decrypted successfully: '{output_filepath}'")

    except InvalidTag:
        _print_error("Decryption failed: Incorrect passphrase or corrupted file (authentication tag mismatch).")
    except ValueError as ve:
        _print_error(f"Decryption failed: {ve}")
    except Exception as e:
        _print_error(f"An unexpected error occurred during decryption: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="A robust file encryption and decryption tool using AES-256-GCM.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        '--mode',
        choices=['encrypt', 'decrypt'],
        required=True,
        help="Operation mode: 'encrypt' to encrypt a file, 'decrypt' to decrypt a file."
    )
    parser.add_argument(
        '--input',
        required=True,
        help="Path to the input file (file to be encrypted or decrypted)."
    )
    parser.add_argument(
        '--output',
        required=True,
        help="Path where the output file will be saved.\n"
             "  - For encryption, it's recommended to append '.encrypted' or '.enc'.\n"
             "  - For decryption, specify the desired original filename."
    )
    parser.add_argument(
        '--passphrase',
        required=True,
        help="The passphrase for encryption/decryption. Use a strong, memorable passphrase."
    )

    args = parser.parse_args()

    if args.mode == 'encrypt':
        encrypt_file(args.input, args.output, args.passphrase)
    elif args.mode == 'decrypt':
        decrypt_file(args.input, args.output, args.passphrase)

if __name__ == "__main__":
    main()
