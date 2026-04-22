
# 🔐 File Upload Attack vs Secure Validation Simulator (Cyber Range)

## 📌 Overview

This project is a **GUI-based Cyber Range Simulation Tool** built in Python to demonstrate how file upload vulnerabilities occur and how they can be prevented using **defense-in-depth validation techniques**.

It provides a **real-time attack vs defense simulation** with a modern cyber dashboard interface.

---

## 🎯 Key Objectives

* Simulate **Unrestricted File Upload vulnerabilities**
* Demonstrate **secure validation mechanisms**
* Provide **real-time visualization of validation process**
* Implement **dynamic whitelist policy management**
* Build a **SOC-style cyber security dashboard**

---

## ⚙️ Features

### 🔴 Attack Mode (Vulnerable System)

* Accepts any file without validation
* Demonstrates:

  * Malicious file upload
  * Extension bypass attacks
  * Lack of security controls
* Logs show insecure behavior

---

### 🟢 Defense Mode (Secure System)

Implements **multi-layer security validation**:

* ✅ Whitelist-based extension filtering
* ✅ MIME type validation
* ✅ File signature (magic bytes) check
* ✅ Content inspection (malicious patterns)
* ✅ File size restriction
* ✅ Secure file renaming (UUID)

---

### ⚡ Real-Time Validation Animation

* Displays validation progress:

```text
Validating.
Validating..
Validating...
```

* Simulates real-world processing delay
* Enhances user understanding of validation stages

---

### 🎨 Cyber Dashboard UI

* Dark-themed professional interface
* Color-coded buttons (Attack/Defense)
* Live logs panel
* Status indicator (READY / SAFE / BLOCKED / RISK)
* Clean structured layout

---

### 🔧 Dynamic Whitelist System

* First-run initialization (mandatory setup)
* Editable via GUI ("Edit Whitelist" button)
* Stored persistently in `whitelist.json`
* Updates reflected in real-time

---

### 📊 Logging System

* Real-time event tracking
* Displays:

  * File details
  * Validation steps
  * Attack detection
  * Final decision
* Color-coded output for clarity

---

## 🧠 Security Concepts Demonstrated

* Unrestricted File Upload
* MIME Spoofing
* File Signature Validation
* Content-Based Detection
* Defense-in-Depth Strategy
* Policy-Based Security (Whitelist)

Aligned with best practices from
👉 OWASP

---

## 📁 Project Structure

```bash
file-upload-simulator/
│
├── main.py                # GUI + simulation controller
├── validator.py           # Secure validation logic
├── attack_simulator.py    # Vulnerable upload logic
├── utils.py               # Helper functions (MIME, whitelist, etc.)
├── logger.py              # Log system
│
├── uploads/               # Vulnerable uploads
├── uploads_secure/        # Secure uploads
│
├── whitelist.json         # Allowed file types (persistent)
└── README.md
```

---

## 🚀 Installation & Setup

### 1️⃣ Clone Repository

```bash
git clone https://github.com/NithinReddy-47/File-Upload-attack-and-defense-simulator.git
cd File-Upload-attack-and-defense-simulator
```

### 2️⃣ Install Dependencies

```bash
pip install python-magic
```

> Windows users:

```bash
pip install python-magic-bin
```

---

### 3️⃣ Run Application

```bash
cd "File Upload simulation"
python main.py
```

---

## 🧪 Testing Scenarios

| File          | Attack Mode | Defense Mode              |
| ------------- | ----------- | ------------------------- |
| image.jpg     | ✅ Allowed   | ✅ Allowed                 |
| shell.php     | ✅ Allowed   | ❌ Blocked                 |
| shell.php.jpg | ✅ Allowed   | ❌ Blocked                 |
| fake.jpg      | ✅ Allowed   | ❌ Blocked (MIME mismatch) |
| malicious.txt | ✅ Allowed   | ❌ Blocked (content scan)  |

---

## ⚠️ Limitations

* Not a full antivirus system
* Cannot detect advanced malware (e.g., polymorphic threats)
* No sandbox execution
* Limited to static and pattern-based analysis

---

## 🔮 Future Enhancements

* File hashing (SHA-256 integrity check)
* Integration with antivirus APIs
* Risk scoring system (LOW / HIGH / CRITICAL)
* Admin-based whitelist control (RBAC integration)
* Web-based version (Flask/Django)

---

## 🎓 Learning Outcomes

* Understanding file upload vulnerabilities
* Importance of layered validation
* Hands-on secure coding practices
* Cyber range simulation experience

---

## 👨‍💻 Author

R. Nithin Reddy 

---

## 📜 License

This project is developed for **educational purposes only**.
