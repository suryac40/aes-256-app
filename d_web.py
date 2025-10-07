import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import io
from PIL import Image

st.set_page_config(page_title="AES-256 Encryptor", layout="centered")

st.title("🔒 AES-256 Encryptor / Decryptor")
st.markdown("Encrypt or decrypt Text, Image, and Audio files securely.")

# --------------------------
# AES Helper Functions
# --------------------------

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def aes_encrypt(data, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data))
    return iv + ciphertext  # prepend IV for decryption

def aes_decrypt(data, key):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext

# --------------------------
# Session State for Key
# --------------------------
if 'aes_key' not in st.session_state:
    st.session_state['aes_key'] = None

# --------------------------
# AES Key Management
# --------------------------
st.subheader("AES Key")
col1, col2, col3 = st.columns(3)

with col1:
    uploaded_key = st.file_uploader("Upload AES Key (.key)", type=["key"])
    if uploaded_key:
        try:
            st.session_state['aes_key'] = uploaded_key.read()
            st.success("✅ Key loaded successfully!")
        except Exception as e:
            st.error("❌ Invalid key file")

with col2:
    if st.button("Generate New Key"):
        st.session_state['aes_key'] = get_random_bytes(32)  # 256-bit key
        st.success("✅ New AES-256 key generated")

with col3:
    if st.session_state['aes_key']:
        st.download_button(
            "Download Key",
            st.session_state['aes_key'],
            file_name="aes_key.key"
        )

# --------------------------
# Mode Selection
# --------------------------
st.subheader("Mode")
mode = st.radio("Choose Mode", ["Encrypt", "Decrypt"])

# --------------------------
# File Type Selection
# --------------------------
st.subheader("File Type")
file_type = st.selectbox("Select File Type", ["Text", "Image", "Audio"])

# --------------------------
# File Upload
# --------------------------
uploaded_file = st.file_uploader("Upload File", type=None)

if uploaded_file and st.session_state['aes_key']:
    file_bytes = uploaded_file.read()

    try:
        if mode == "Encrypt":
            result = aes_encrypt(file_bytes, st.session_state['aes_key'])
            st.success("✅ Encryption Complete!")
            st.info("Encrypted file cannot be previewed. Please download it.")
        else:  # Decrypt
            result = aes_decrypt(file_bytes, st.session_state['aes_key'])
            st.success("✅ Decryption Complete!")

            # Preview only for decrypted files
            if file_type == "Text":
                try:
                    st.text(result.decode())
                except:
                    st.text("Cannot preview this text (binary content)")
            elif file_type == "Image":
                try:
                    image = Image.open(io.BytesIO(result))
                    st.image(image, caption="Preview", use_container_width=True)
                except:
                    st.text("Cannot preview this image")
            elif file_type == "Audio":
                st.audio(result)

        # --------------------------
        # Download Result
        # --------------------------
        output_name = uploaded_file.name
        if mode == "Encrypt" and not output_name.endswith(".enc"):
            output_name += ".enc"
        elif mode == "Decrypt":
            output_name = output_name.replace(".enc", "_decrypted")

        st.download_button(f"Download {mode}ed File", result, output_name)

    except Exception as e:
        st.error(f"❌ Error: {e}")

elif uploaded_file and not st.session_state['aes_key']:
    st.warning("⚠️ Please upload or generate an AES key first.")
