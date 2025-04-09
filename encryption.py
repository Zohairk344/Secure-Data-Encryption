import streamlit as st
import os
import json
import base64
import time

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ---------- Configuration & File Paths ----------
DATA_FILE = "data.json"  # File to store user data entries

# ---------- Utility Functions for Data Persistence ----------
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    else:
        return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# ---------- Key Derivation and Password Hashing ----------
def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key using PBKDF2HMAC from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def hash_password(password: str, salt: bytes) -> str:
    """Creates a password hash using PBKDF2 key derivation."""
    key = derive_key(password, salt)
    # Return the derived key as a string
    return key.decode()

def verify_password(password: str, salt: bytes, stored_hash: str) -> bool:
    """Verifies that the provided password produces the same hash using the provided salt."""
    return hash_password(password, salt) == stored_hash

# ---------- User Management ----------
# For demonstration, we store users in session_state["users"].
# A real-world app should store these securely in a persistent database.
if "users" not in st.session_state:
    # Pre-load one demo user: username "user1", password "pass1"
    user_salt = os.urandom(16)
    st.session_state.users = {
        "user1": {
            "salt": base64.b64encode(user_salt).decode(),
            "pass_hash": hash_password("pass1", user_salt)
        }
    }

def register_user(username: str, password: str) -> bool:
    """Registers a new user if the username is not already taken."""
    if username in st.session_state.users:
        return False
    new_salt = os.urandom(16)
    st.session_state.users[username] = {
        "salt": base64.b64encode(new_salt).decode(),
        "pass_hash": hash_password(password, new_salt)
    }
    return True

# ---------- Authentication Functions ----------
def login(username: str, password: str) -> bool:
    users = st.session_state.users
    if username in users:
        salt = base64.b64decode(users[username]["salt"])
        if verify_password(password, salt, users[username]["pass_hash"]):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
            return True
    return False

def logout():
    st.session_state.logged_in = False
    st.session_state.username = None

# ---------- Initialize Session State Variables ----------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None
if "auth_mode" not in st.session_state:
    st.session_state.auth_mode = "Login"  # or "Sign Up"

# ---------- Authentication Pages ----------
def show_login():
    st.title("Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login"):
        lockout_duration = 60  # seconds
        if st.session_state.lockout_time and time.time() - st.session_state.lockout_time < lockout_duration:
            st.error("Too many failed attempts. Please wait before trying again.")
        else:
            if login(username, password):
                st.success("Logged in successfully!")
                if hasattr(st, "experimental_rerun"):
                    st.experimental_rerun()
                else:
                    st.stop()
            else:
                st.error("Invalid credentials.")
    st.info("Demo credentials: username: user1, password: pass1")
    if st.button("Switch to Sign Up"):
        st.session_state.auth_mode = "Sign Up"
        if hasattr(st, "experimental_rerun"):
            st.experimental_rerun()
        else:
            st.stop()


def show_signup():
    st.title("Sign Up")
    new_username = st.text_input("Choose a username", key="signup_username")
    new_password = st.text_input("Choose a password", type="password", key="signup_password")
    confirm_password = st.text_input("Confirm password", type="password", key="signup_confirm")
    if st.button("Register"):
        if not new_username or not new_password or not confirm_password:
            st.error("Please fill in all fields.")
        elif new_password != confirm_password:
            st.error("Passwords do not match.")
        elif new_username in st.session_state.users:
            st.error("Username already exists. Please choose another.")
        else:
            if register_user(new_username, new_password):
                st.success("Registration successful! You can now log in.")
                st.session_state.auth_mode = "Login"
                if hasattr(st, "experimental_rerun"):
                    st.experimental_rerun()
                else:
                    st.stop()
            else:
                st.error("Registration failed. Please try again.")
    if st.button("Switch to Login"):
        st.session_state.auth_mode = "Login"
        if hasattr(st, "experimental_rerun"):
            st.experimental_rerun()
        else:
            st.stop()


# ---------- Main Auth Page for Non-Logged-In Users ----------
def show_auth():
    auth_mode = st.session_state.auth_mode
    if auth_mode == "Login":
        show_login()
    else:
        show_signup()

# ---------- App Pages (available after login) ----------
def show_home():
    st.title("Home")
    st.write(f"Welcome, {st.session_state.username}!")
    st.write("Select an option from the sidebar.")

def show_store_data():
    st.title("Store New Data")
    text = st.text_area("Enter the text you wish to encrypt and store:")
    passkey = st.text_input("Enter a unique passkey for this data:", type="password")
    if st.button("Store Data"):
        if not text or not passkey:
            st.error("Please provide both text and passkey.")
            return

        # Generate two independent salts: one for encryption key derivation and one for passkey hashing.
        enc_salt = os.urandom(16)
        hash_salt = os.urandom(16)

        # Derive the encryption key from the entered passkey and enc_salt.
        key = derive_key(passkey, enc_salt)
        cipher = Fernet(key)
        try:
            encrypted_text = cipher.encrypt(text.encode()).decode()
        except Exception as e:
            st.error(f"Encryption error: {e}")
            return

        # Compute passkey hash for verification.
        pass_hash = hash_password(passkey, hash_salt)

        # Load current stored data from JSON.
        data = load_data()
        username = st.session_state.username
        if username not in data:
            data[username] = []

        # Create a new record.
        entry = {
            "encrypted_text": encrypted_text,
            "enc_salt": base64.b64encode(enc_salt).decode(),
            "pass_hash": pass_hash,
            "hash_salt": base64.b64encode(hash_salt).decode(),
            "timestamp": time.time()
        }
        data[username].append(entry)
        save_data(data)
        st.success("Data stored securely!")

def show_retrieve_data():
    st.title("Retrieve Data")
    data = load_data()
    username = st.session_state.username
    if username not in data or not data[username]:
        st.info("No data entries found for your account.")
        return

    st.write("Your stored data entries:")
    for idx, entry in enumerate(data[username]):
        st.write(f"Entry {idx + 1}: stored at {time.ctime(entry.get('timestamp', 0))}")

    entry_idx = st.number_input("Enter the entry number to decrypt:", min_value=1, max_value=len(data[username]), step=1)
    passkey = st.text_input("Enter the passkey for this entry:", type="password")

    if st.button("Decrypt"):
        lockout_duration = 60  # seconds
        if st.session_state.lockout_time and time.time() - st.session_state.lockout_time < lockout_duration:
            st.error("Too many failed attempts. Please wait before trying again.")
            return

        selected_entry = data[username][entry_idx - 1]
        stored_hash = selected_entry["pass_hash"]
        hash_salt = base64.b64decode(selected_entry["hash_salt"])
        if not verify_password(passkey, hash_salt, stored_hash):
            st.error("Incorrect passkey.")
            st.session_state.failed_attempts += 1
            st.write(f"Failed attempts: {st.session_state.failed_attempts}")
            if st.session_state.failed_attempts >= 3:
                st.error("Too many failed attempts. Logging out for security.")
                st.session_state.lockout_time = time.time()
                logout()
                st.experimental_rerun()
            return

        enc_salt = base64.b64decode(selected_entry["enc_salt"])
        key = derive_key(passkey, enc_salt)
        cipher = Fernet(key)
        try:
            decrypted = cipher.decrypt(selected_entry["encrypted_text"].encode()).decode()
            st.success("Data decrypted successfully!")
            st.write("Decrypted Data:", decrypted)
            st.session_state.failed_attempts = 0  # reset on success
        except InvalidToken:
            st.error("Decryption failed. The passkey may be incorrect.")
            st.session_state.failed_attempts += 1
            st.write(f"Failed attempts: {st.session_state.failed_attempts}")
            if st.session_state.failed_attempts >= 3:
                st.error("Too many failed attempts. Logging out.")
                st.session_state.lockout_time = time.time()
                logout()
                st.experimental_rerun()
        except Exception as e:
            st.error(f"Decryption error: {e}")

# ---------- Sidebar Navigation ----------
def navigation():
    menu = st.sidebar.radio("Navigation", ["Home", "Store Data", "Retrieve Data", "Logout"])
    if menu == "Home":
        show_home()
    elif menu == "Store Data":
        show_store_data()
    elif menu == "Retrieve Data":
        show_retrieve_data()
    elif menu == "Logout":
        logout()
        st.success("Logged out successfully.")
        # Instead of a direct call to st.experimental_rerun(), check if it's available:
        if hasattr(st, "experimental_rerun"):
            st.experimental_rerun()
        else:
            st.stop()


# ---------- Main App ----------
def main():
    if not st.session_state.logged_in:
        show_auth()  # Show login or sign up page based on auth_mode
    else:
        navigation()

if __name__ == "__main__":
    main()
