# CIFER v3 — Secure File Encryption System
# Flask + MySQL + AES-256 + Gmail OTP

## ═══ WINDOWS SETUP (Step by Step) ═══

### Step 1 — Install Python (if not installed)
Download from https://python.org → During install, CHECK "Add Python to PATH"

### Step 2 — Install MySQL
Download MySQL Installer from https://dev.mysql.com/downloads/installer/
Install MySQL Server + MySQL Workbench (for viewing data)

### Step 3 — Extract CIFER-V3.zip
Right-click → Extract All → choose Desktop or any folder
Open the extracted CIFER-V3 folder — you should see:
  backend/
  frontend/
  README.md

### Step 4 — Open PowerShell IN the CIFER-V3 folder
Right-click on empty area inside CIFER-V3 folder → "Open in Terminal"
OR: Press Windows + R → type powershell → cd to your folder

### Step 5 — Create Python virtual environment
```powershell
c
venv\Scripts\activate
```
You should see (venv) at the start of the prompt.

### Step 6 — Install dependencies
```powershell
cd backend
pip install -r requirements.txt
```

### Step 7 — Set up MySQL database
Open MySQL Workbench or MySQL command line:
```sql
mysql -u root -p
```
Enter your MySQL root password, then:
```sql
SOURCE schema.sql;
EXIT;
```
OR in MySQL Workbench: File → Open SQL Script → select schema.sql → Execute

### Step 8 — Configure .env
```powershell
Copy-Item .env.example .env
notepad .env
```
Fill in:
```
SECRET_KEY=any_long_random_string_here
DB_HOST=localhost
DB_USER=root
DB_PASS=your_mysql_password
DB_NAME=cifer_db
MAIL_USER=yourgmail@gmail.com
MAIL_PASS=your_16_char_app_password
SERVER_KEY=generate_64_hex_chars_see_below
FLASK_ENV=development
```

### Step 9 — Generate SERVER_KEY
In PowerShell (with venv active):
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```
Copy output → paste into .env as SERVER_KEY

### Step 10 — Get Gmail App Password
1. Go to https://myaccount.google.com
2. Security → 2-Step Verification → enable it
3. Security → App Passwords → Select "Mail" → Generate
4. Copy the 16-character password → paste into .env as MAIL_PASS

### Step 11 — Start Flask server
```powershell
python app.py
```
You should see: * Running on http://127.0.0.1:5000

### Step 12 — Open website
Open index.html in your browser:
→ Double-click frontend/index.html
OR use VS Code Live Server extension (recommended)

## ═══ PAGES ═══
- Home:     frontend/index.html
- Login:    frontend/pages/login.html
- Encrypt:  frontend/pages/encrypt.html
- Decrypt:  frontend/pages/decrypt.html
- History:  frontend/pages/history.html
- Profile:  frontend/pages/profile.html
- About:    frontend/pages/about.html
- Features: frontend/pages/features.html

## ═══ API ENDPOINTS ═══
POST /api/register      — Create account
POST /api/login         — Login
POST /api/logout        — Logout
GET  /api/me            — Current user + stats
POST /api/encrypt       — Encrypt file (multipart)
GET  /api/file/<token>  — File info
POST /api/request-otp   — Send OTP to receiver email
POST /api/decrypt       — Verify OTP, stream decrypted file
GET  /api/history       — Activity log
GET  /api/active-files  — User's active encrypted files

## ═══ TROUBLESHOOTING ═══

"Cannot connect to server": Make sure `python app.py` is running in PowerShell
"Email error": Check MAIL_USER and MAIL_PASS in .env — use Gmail App Password, not login password
"Database error": Make sure MySQL is running and you ran schema.sql
"Module not found": Run `pip install -r requirements.txt` with venv active

## ═══ DEV MODE OTP ═══
When FLASK_ENV=development and email fails, the OTP is shown in:
1. Flask terminal output (console)
2. Browser dev console toast (yellow warning)
