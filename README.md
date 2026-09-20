# Cryptography Site

A Flask web application that provides user authentication, key generation, symmetric and asymmetric file encryption, secure hashing, password generation, and ECDH key sharing.

## Features

- User registration and login with hashed passwords
- Add and remove users (admin users)
- AES encryption at 128, 192, and 256 bits with CBC and GCM modes
- 3DES encryption with CBC and CFB modes
- Optional 32-bit IV selection
- RSA public/private key encryption using an AES hybrid scheme
- SHA-256 and SHA3-256 file hashing and comparison
- Password generation up to 63 characters
- ECDH key sharing and shared secret derivation
- Upload, download, and delete files and keys

## Requirements

- Python 3.11 or later
- Windows, macOS, or Linux

## Local Setup

1. Open a terminal and change to the project folder:

    cd crypto_site

2. Create a virtual environment (recommended):

    python -m venv venv

3. Activate the virtual environment:

    - On macOS/Linux: source venv/bin/activate
    - On Windows: venv\Scripts\activate

4. Install dependencies:

    pip install -r requirements.txt

5. Run the development server:

    python -m flask --app app.py run --host=0.0.0.0 --port=5000

    Or run with Waitress for a production-ready local server:

    python run.py

6. Open a browser and go to `http://localhost:5000`.

The first user to register is automatically an administrator. After that, only logged-in administrators can add or remove other users.

## Deployment

This app can be deployed to Render for free.

1. Create a GitHub repository and push the project files.
2. Sign up for a free Render account.
3. Create a new Web Service and connect the GitHub repository.
4. Use the following settings:
    - Build command: `pip install -r requirements.txt`
    - Start command: `waitress-serve --port=$PORT app:app`
5. Add an environment variable named `SECRET_KEY` with a long random string.

Once deployed, the site will be accessible from any computer or phone with a browser.

## Important Notes

- Private keys are stored on the server as PEM files. For a real production deployment, store them encrypted or in a hardware security module.
- Set a strong `SECRET_KEY` environment variable before deploying.
- The default file upload size limit is 16 MB.
