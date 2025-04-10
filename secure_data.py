import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64
import time

# --- In-memory storage ---
secure_storage = {}
user_sessions = {}
MAX_ATTEMPTS = 3

# --- Generate key from passkey ---
def generate_key(passkey: str) -> bytes:
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

# --- Encrypt data ---
def encrypt_data(data: str, key: bytes) -> str:
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

# --- Decrypt data ---
def decrypt_data(data: str, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(data.encode()).decode()

# --- Login Page ---
def login():
    st.title("🔐 Secure Data Encryption System")
    st.markdown("""
        <style>
            .title {color: #4CAF50; font-size: 24px; font-weight: bold;}
        </style>
    """, unsafe_allow_html=True)

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    login_button = st.button("Login")

    if login_button:
        if username and password:
            st.session_state['user'] = username
            st.session_state['attempts'] = 0
            st.success("Logged in successfully!")
            time.sleep(1)
            st.experimental_rerun()
        else:
            st.error("Please enter both username and password.")

# --- Main App ---
def secure_app():
    st.title("🛡️ Secure Data Storage")
    st.markdown("---")
    st.sidebar.success(f"Logged in as {st.session_state['user']}")

    option = st.selectbox("Choose an action", ["Store Data", "Retrieve Data"])

    if option == "Store Data":
        data = st.text_area("Enter your secret data:")
        passkey = st.text_input("Enter a passkey to encrypt data:", type="password")
        if st.button("Encrypt & Store"):
            if data and passkey:
                key = generate_key(passkey)
                encrypted = encrypt_data(data, key)
                secure_storage[st.session_state['user']] = encrypted
                st.success("Data encrypted and stored successfully!")
            else:
                st.warning("Please provide both data and passkey.")

    elif option == "Retrieve Data":
        if st.session_state['user'] not in secure_storage:
            st.info("No data stored for this user.")
            return

        passkey = st.text_input("Enter your passkey to decrypt data:", type="password")
        if st.button("Decrypt"):
            if passkey:
                key = generate_key(passkey)
                try:
                    decrypted = decrypt_data(secure_storage[st.session_state['user']], key)
                    st.success("Data decrypted successfully:")
                    st.code(decrypted)
                    st.session_state['attempts'] = 0
                except:
                    st.session_state['attempts'] += 1
                    st.error("Incorrect passkey!")
                    if st.session_state['attempts'] >= MAX_ATTEMPTS:
                        st.error("Too many failed attempts. Redirecting to login.")
                        time.sleep(2)
                        del st.session_state['user']
                        st.experimental_rerun()
            else:
                st.warning("Please enter a passkey.")

# --- App Flow ---
if 'user' not in st.session_state:
    login()
elif st.session_state.get('attempts', 0) >= MAX_ATTEMPTS:
    st.error("Too many failed attempts. Please login again.")
    login()
else:
    secure_app()
