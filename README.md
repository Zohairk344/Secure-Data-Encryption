# Streamlit Encryption and Multi-Page Authentication App

A secure data storage and retrieval system built with Streamlit. This app features:
- **User Authentication:** Login and Sign-Up functionality with secure password hashing (using PBKDF2).
- **Data Encryption:** Encrypt and decrypt text using Fernet (from the Cryptography library) with keys derived via PBKDF2 from a user-supplied passkey.
- **Data Persistence:** Store each user's encrypted data in a JSON file.
- **Security Measures:** Track and limit failed attempts with lockout enforcement.
- **Multi-Page Navigation:** Seamlessly switch between Home, Store Data, Retrieve Data, and Logout pages via a sidebar.

---

press login/signup page twice if it doesnt work.

## Features

- **User Registration and Login:**  
  New users can sign up by choosing a username and password; registered users log in to access secure features.
  
- **Encryption & Decryption:**  
  Data is encrypted using Fernet with an encryption key derived using PBKDF2 (with random salts), then decrypted if the correct passkey is provided.
  
- **Persistent Data Storage:**  
  Users' encrypted records are saved in a JSON file (`data.json`), so data persists across app sessions.
  
- **Lockout Mechanism:**  
  The app tracks failed decryption or password attempts. After three failures, it locks the user out temporarily by forcing a logout.
  
- **Multi-Page Interface:**  
  A sidebar lets users navigate between the Home page, data storage, data retrieval, and logout options.

---

## Requirements

- Python 3.7 or higher
- [Streamlit](https://streamlit.io/)
- [Cryptography](https://cryptography.io/)

---

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/your-repo.git
   cd your-repo
Install the required dependencies:

bash
Copy
Edit
pip install streamlit cryptography
Running the App
Start the app using Streamlit:

bash
Copy
Edit
streamlit run app.py
The app will open in your default web browser at http://localhost:8501. Use the sidebar to switch between “Login / Sign Up” and authenticated pages.

File Structure
pgsql
Copy
Edit
.
├── app.py         # Main Streamlit app file with authentication and encryption logic
├── data.json      # JSON file that stores the encrypted user data entries
└── README.md      # This file
Usage
Sign Up:
On the authentication page, switch to "Sign Up" to register a new account. Fill in the username, password, and confirm the password. (For demonstration, registered details are stored in the session state.)

Login:
After registration (or using demo credentials, e.g., username: user1, password: pass1), log in via the Login page.

Store Data:
Once logged in, navigate to "Store Data" to input text and a unique passkey. The app encrypts your text using Fernet, and stores the encrypted message, along with necessary salts and passkey hash, in the JSON file.

Retrieve Data:
Navigate to "Retrieve Data" to select an entry by its number and enter the corresponding passkey to decrypt the text.

Logout:
Use the "Logout" option in the sidebar to end the session.

Security Considerations
Key Management:
Encryption keys are derived on the fly from user-supplied passkeys and random salts, so neither keys nor raw passwords are stored.

Password Hashing:
User passwords are hashed using PBKDF2 with a random salt. In this demo, user credentials are stored only in the session state (volatile), so they are not persisted on disk.

Failed Attempts:
A counter tracks failed decryption or login attempts. After three failures, the user is temporarily locked out and forced to log in again.

Data Storage:
Encrypted data (with salts and hashes) is saved to a JSON file (data.json). For production, consider using a secure, persistent database.

Limitations and Future Improvements
Persistent User Registration:
Currently, user registration details are stored in session state and not persisted across app restarts. Integrating a persistent database is recommended for production use.

UI Enhancements:
The current UI uses basic Streamlit components. For improved usability and appearance, consider incorporating custom CSS or additional Streamlit components.

Security Enhancements:
Further security measures (such as multi-factor authentication or a more robust user management system) can be implemented for enhanced protection.

Contributing
Contributions are welcome! If you have suggestions for improvements, additional features, or bug fixes, please open an issue or submit a pull request.

License
This project is licensed under the MIT License. See the LICENSE file for details.

