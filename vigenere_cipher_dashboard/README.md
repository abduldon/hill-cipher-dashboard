# CRYPTLAB — Hill Cipher Dashboard

A responsive Flask dashboard demonstrating the Hill Cipher with 2×2 and 3×3 key matrices. It includes encryption/decryption, modular matrix calculations, matrix invertibility validation, history, statistics, copy/download, and a learning page.

## Features
- Login with hashed password storage and Flask sessions
- 2×2 and 3×3 Hill Cipher encryption and decryption
- Key-matrix input validation and determinant invertibility check modulo 26
- Step-by-step block calculations, determinant and inverse matrix details
- SQLite-backed operation history and statistics using Flask-SQLAlchemy
- Copy result and download as a text file
- Responsive UI

## Stack
Python, Flask, Flask-SQLAlchemy, SQLite (default), Bootstrap 5, JavaScript, Font Awesome, Gunicorn.

## Run locally (Windows PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000.
link: https://hill-cipher-dashboard.onrender.com/dashboard

## Demo login
Username: `admin`  
Password: `admin123`

Set `ADMIN_PASSWORD` before first startup for a different initial admin password. Change the default before any public deployment. Set a strong random `SECRET_KEY` in the hosting provider's environment variables.

## Matrix input format
Rows are separated by semicolons and values by commas. Example 2×2: `3, 3; 2, 5`. Example 3×3: `6, 24, 1; 13, 16, 10; 20, 17, 15`.

The determinant must be coprime to 26 (`gcd(det(K), 26) = 1`) so its modular inverse exists. Encryption pads the final incomplete block with `X`; the padding is shown in the result and must be handled by the user when interpreting plaintext.


## Security note
The Hill Cipher is historical and not secure for real data. Use this project for educational demonstrations only.
