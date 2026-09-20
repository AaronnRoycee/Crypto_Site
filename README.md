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

## Push to GitHub

1. Create a new empty GitHub repository.
2. In the project folder, run:

    git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
    git branch -M main
    git push -u origin main

3. Git will ask for your GitHub username and a Personal Access Token. Create a token at `https://github.com/settings/tokens` with `repo` scope.

## Deploy on Render

1. Sign up for a free Render account.
2. Click **New +** and choose **Web Service**.
3. Connect the GitHub repository you just pushed.
4. Render will read the `render.yaml` file and set the build and start commands automatically.
5. After the first deploy, open the URL shown in the Render dashboard.

The first user to register on the live site becomes the administrator.

## Important Notes

- Private keys are stored on the server as PEM files. For a real production deployment, store them encrypted or in a hardware security module.
- Set a strong `SECRET_KEY` environment variable before deploying.
- The default file upload size limit is 16 MB.
