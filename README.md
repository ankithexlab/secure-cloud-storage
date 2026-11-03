# CipherVault — Secure Cloud File Storage and Privacy Protection Portal

**CipherVault** is a secure cloud-based file storage and privacy protection application designed to protect sensitive files through client-side encryption, controlled access, secure sharing, and personally identifiable information (PII) masking.

The project demonstrates how modern cryptographic techniques and cloud storage can be integrated into a web application to improve data confidentiality and privacy.

## Key Features

- **Secure Authentication:** JWT-based authentication and bcrypt password hashing.
- **AES-256-GCM Encryption:** Encrypt files before uploading them to cloud storage.
- **RSA Public-Key Cryptography:** RSA-OAEP 2048-bit key pair for secure key exchange.
- **Hybrid Encryption:** Protect file encryption keys using RSA.
- **Cloud Storage:** Backblaze B2 integration using its S3-compatible API.
- **Secure File Sharing:** Share files with registered users using recipient public keys.
- **Access Token Management:** Generate, manage, and revoke secure access tokens.
- **PII Detection and Masking:** Detect and mask supported sensitive information.
- **Audit Logging:** Maintain security-related activity records.
- **File Integrity:** SHA-256 hashing for integrity verification.

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | React.js 18 |
| Styling | Tailwind CSS |
| Backend | Python Flask |
| Database | MongoDB |
| Cloud Storage | Backblaze B2 |
| Authentication | JWT, bcrypt |
| Symmetric Encryption | AES-256-GCM |
| Asymmetric Encryption | RSA-OAEP 2048-bit |
| Key Derivation | PBKDF2-SHA256 |
| Integrity | SHA-256 |
| API Communication | Axios |

## System Architecture

```text
                 User
                  |
                  v
          React Frontend
                  |
          Authentication
                  |
          Flask REST API
             /        \
            v          v
        MongoDB     Backblaze B2
            |          |
       User Data    Encrypted Files
       File Metadata
       Sharing Data
       Audit Logs
```

File encryption and decryption are performed on the client side. The cloud storage service stores encrypted file content.

## Project Structure

```text
secure-cloud/
│
├── backend/
│   ├── app.py
│   ├── config.py
│   ├── models/
│   ├── routes/
│   ├── utils/
│   ├── tests/
│   └── requirements.txt
│
├── frontend/
│   ├── public/
│   ├── src/
│   └── package.json
│
├── .gitignore
└── README.md
```

## Prerequisites

Install the following before running the project:

- Python 3.10 or later
- Node.js and npm
- MongoDB
- Backblaze B2 account and private bucket
- Git

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/ankithexlab/secure-cloud-storage.git
cd secure-cloud-storage
```

### 2. Backend Setup

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
python -m venv backend/venv
.\backend\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r backend/requirements.txt
```

### 3. Backend Environment Configuration

Create a `.env` file inside the `backend` directory.

```env
FLASK_ENV=development

SECRET_KEY=replace_with_a_secure_random_secret
JWT_SECRET_KEY=replace_with_another_secure_random_secret

MONGODB_URI=mongodb://127.0.0.1:27017/securecloud
MONGODB_DB_NAME=securecloud

B2_KEY_ID=your_backblaze_key_id
B2_APPLICATION_KEY=your_backblaze_application_key
B2_BUCKET_NAME=your_private_bucket_name
B2_ENDPOINT_URL=https://s3.us-east-005.backblazeb2.com

AWS_REGION=us-east-005

CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

Replace the example values with your own configuration. Never commit real credentials or secret keys.

### 4. Start the Backend

Make sure MongoDB is running, then execute:

```powershell
python backend/app.py
```

Backend API:

```text
http://127.0.0.1:5000
```

### 5. Frontend Setup

Open another terminal:

```powershell
cd frontend
npm install
```

Optionally, create `frontend/.env` to configure the API URL:

```env
REACT_APP_API_URL=http://127.0.0.1:5000/api
```

Start the frontend:

```powershell
npm start
```

Open the application:

```text
http://localhost:3000
```

## Running Tests

### Backend Tests

From the project root, with the backend environment activated:

```powershell
python -m pytest backend/tests -v
```

### Frontend Tests

```powershell
cd frontend
npm test
```

### Production Build

```powershell
npm run build
```

## Security Considerations

- Keep all environment files and credentials private.
- Use strong, randomly generated secrets in production.
- Keep the Backblaze B2 bucket private.
- Never expose private keys or application credentials in frontend code.
- Use HTTPS in production.
- Review access permissions and token expiration settings.
- Do not use development secret defaults in production.

## File Upload Limit

Maximum supported original file size: **50 MB**.

## Project Purpose

This project was developed as an academic cybersecurity project to demonstrate secure cloud file storage, cryptographic protection, authentication, access control, and privacy-preserving file sharing.

## Disclaimer

CipherVault is an academic project. It should undergo independent security review and production hardening before being used to store real sensitive information.

## Author

**Ankit Kumar**

GitHub: https://github.com/ankithexlab

---

**Repository:** https://github.com/ankithexlab/secure-cloud-storage
