import streamlit as st
from cryptography.fernet import Fernet
import base64

# ---------- UI Styling ----------
st.set_page_config(page_title="🔐 Secure Encryption App", layout="centered")
st.markdown(
    """
    <style>
    .main {
        background-color: #fdf6f0;
    }
    .stButton>button {
        color: white;
        background: linear-gradient(to right, #0f2027, #203a43, #2c5364);
        border-radius: 10px;
        padding: 10px 20px;
        border: none;
    }
    .stTextInput>div>div>input {
        background-color: #ffffff;
        color: #333333;
    }
    .big-font {
        font-size:22px !important;
        color: #44475a;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------- App Title ----------
st.markdown("<h1 style='text-align: center; color: #6c5ce7;'>🔐 Secure Data Encryption</h1>", unsafe_allow_html=True)
st.markdown("<p class='big-font' style='text-align: center;'>Encrypt and decrypt your sensitive data with ease and beauty!</p>", unsafe_allow_html=True)
st.markdown("---")

# ---------- Key Management ----------
st.subheader("🔑 Generate or Paste Encryption Key")
use_existing = st.checkbox("Use my own key")

if use_existing:
    key_input = st.text_input("Paste your Fernet key here", type="password")
    try:
        key = key_input.encode()
        fernet = Fernet(key)
    except Exception:
        st.error("Invalid key. Please make sure it's a valid Fernet key.")
        fernet = None
else:
    key = Fernet.generate_key()
    fernet = Fernet(key)
    st.success("🔑 Your Encryption Key (save it securely!)")
    st.code(key.decode())

st.markdown("---")

# ---------- Encryption / Decryption ----------
option = st.radio("Choose Action", ["🔏 Encrypt", "🔓 Decrypt"], horizontal=True)

if option == "🔏 Encrypt":
    plain_text = st.text_area("Enter the message to encrypt", height=150)
    if st.button("✨ Encrypt"):
        if plain_text and fernet:
            encrypted_text = fernet.encrypt(plain_text.encode()).decode()
            st.success("✅ Encrypted Successfully!")
            st.text_area("🔐 Encrypted Text", encrypted_text, height=150)
            st.download_button("📥 Download Encrypted Text", encrypted_text, file_name="encrypted.txt")
        else:
            st.warning("Please enter text and ensure a valid key.")

elif option == "🔓 Decrypt":
    encrypted_text = st.text_area("Enter the encrypted message", height=150)
    if st.button("🔍 Decrypt"):
        try:
            if encrypted_text and fernet:
                decrypted_text = fernet.decrypt(encrypted_text.encode()).decode()
                st.success("✅ Decrypted Successfully!")
                st.text_area("💬 Decrypted Text", decrypted_text, height=150)
            else:
                st.warning("Please enter encrypted text and ensure a valid key.")
        except Exception as e:
            st.error("❌ Failed to decrypt. Check your key or the message.")

# ---------- Footer ----------
st.markdown("---")
st.markdown("<p style='text-align: center; font-size: 14px;'>🌟 Built with love from AFSHAN by using Streamlit & Cryptography 🌟</p>", unsafe_allow_html=True)
