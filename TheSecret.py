import streamlit as st
from PIL import Image
import numpy as np
import io
from cryptography.fernet import Fernet
import base64
import hashlib
import zlib

# Function Definitions

def generate_key(password):
    """Generate a key based on the user-provided password."""
    key = hashlib.sha256(password.encode()).digest()[:32]
    return base64.urlsafe_b64encode(key)

def compress_message(message):
    """Compress the message using zlib."""
    return zlib.compress(message.encode())

def decompress_message(compressed_message):
    """Decompress the message using zlib."""
    return zlib.decompress(compressed_message).decode()

def encrypt_message(message, password):
    """Encrypt the message using the user-provided password."""
    key = generate_key(password)
    cipher = Fernet(key)
    compressed_message = compress_message(message)
    encrypted_message = cipher.encrypt(compressed_message)
    return encrypted_message

def decrypt_message(encrypted_message, password):
    """Decrypt the encrypted message using the user-provided password."""
    key = generate_key(password)
    cipher = Fernet(key)
    compressed_message = cipher.decrypt(encrypted_message)
    return decompress_message(compressed_message)

def encode_lsb(image, message, password):
    encrypted_message = encrypt_message(message, password)
    binary_message = ''.join([format(byte, '08b') for byte in encrypted_message])
    image = image.convert("RGB")
    pixels = np.array(image)
    total_pixels = pixels.size // 3

    if len(binary_message) > total_pixels:
        raise ValueError(f"Message is too long to be hidden in this image. Max characters: {total_pixels // 8}")

    index = 0
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):
                if index < len(binary_message):
                    pixels[i, j, k] = (pixels[i, j, k] & ~1) | int(binary_message[index])
                    index += 1

    encoded_image = Image.fromarray(pixels)
    encoded_image_bytes = io.BytesIO()
    encoded_image.save(encoded_image_bytes, format='PNG')
    return encoded_image_bytes.getvalue()

def decode_lsb(image, password):
    image = image.convert("RGB")
    pixels = np.array(image)
    binary_message = ""

    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):
                binary_message += str(pixels[i, j, k] & 1)

    byte_data = [int(binary_message[i:i+8], 2) for i in range(0, len(binary_message), 8)]
    encrypted_message = bytes(byte_data)

    try:
        decoded_message = decrypt_message(encrypted_message, password)
    except Exception:
        raise ValueError("Failed to decrypt message. The password might be incorrect.")
    
    return decoded_message

# Streamlit Interface
st.title(" Secret Chatting App using Image Steganography & Encryption")
st.markdown(
    """
    Welcome to the **Secret Chatting App**! Here you can securely encode and decode secret messages within images. 
    Just upload an image, enter your secret message, and set a password to keep your secrets safe! 
    """
)

# Upload image
uploaded_image = st.file_uploader(" Upload an Image", type=["png", "jpg", "jpeg", "bmp"])
if uploaded_image:
    image = Image.open(uploaded_image)
    st.image(image, caption="Uploaded Image", use_column_width=True)
    
    # Calculate max characters based on image size
    total_pixels = np.array(image).size // 3
    max_chars = total_pixels // 8

    # Encode Section
    st.subheader("Encode a Message ")
    message = st.text_area(f"Enter a secret message to encode (Max {max_chars} characters)")
    password = st.text_input("Enter a password for encryption", type="password", help="Choose a strong password for encryption.")
    
    message_length = len(message)
    st.write(f" Characters: {message_length} / {max_chars}")

    if st.button(" Encode Message"):
        if message_length > max_chars:
            st.error(f"Message too long! Please keep it under {max_chars} characters.")
        elif not password:
            st.error("Password cannot be empty!")
        else:
            try:
                with st.spinner("Encoding in progress..."):
                    encoded_image_data = encode_lsb(image, message, password)
                    st.success("Message encoded and encrypted successfully! ")

                    st.download_button(
                        label=" Download Encoded Image",
                        data=encoded_image_data,
                        file_name="encoded_image.png",
                        mime="image/png"
                    )
            except ValueError as ve:
                st.error(f"Error: {ve}")
            except Exception as e:
                st.error(f"An unexpected error occurred: {e}")

    # Decode Section
    st.subheader("Decode a Message ")
    password_decode = st.text_input("Enter the password to decrypt", type="password", help="Enter the password used during encoding.")
    
    if st.button(" Decode Message"):
        try:
            with st.spinner("Decoding in progress..."):
                decoded_message = decode_lsb(image, password_decode)
                st.success("Message decoded successfully! ")
                st.write(f"Decoded Message: **{decoded_message}**")
        except ValueError as ve:
            st.error(f"Error: {ve}")
        except Exception as e:
            st.error(f"Error decoding message: {e}")
