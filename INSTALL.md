# Hermes: Encrypted Query Processing via MySQL + OpenFHE

Hermes is a homomorphic encryption plugin for MySQL using the OpenFHE library (BFV scheme). It supports compile-time encryption, secure ciphertext storage, SQL-compatible decryption, aggregation, and homomorphic multiplication—all as native UDFs callable from SQL.

---

## 📦 System Requirements

Ensure the following dependencies are installed:

### Required Packages

- **MySQL Server (>= 8.0)**
- **OpenFHE (>= v1.1.1)** with BFV scheme support
- **CMake (>= 3.10)**
- **g++ (>= 9.4)** or any C++17-compatible compiler
- **libmysqlclient-dev**
- **Python 3** (for helper scripts)

Install essentials via:

```bash
sudo apt update
sudo apt install mysql-server libmysqlclient-dev cmake g++ build-essential python3
```

---

## 🔁 OpenFHE Compatibility

All testing is performed using the following fork:

👉 <https://github.com/hpdic/openfhe-development>

⚠️ Compatibility with upstream OpenFHE is **not guaranteed** due to possible API differences.

---

## 🔧 Installation Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/hpdic/hermes.git
cd hermes
```

### 2. Build and Register the Plugin

This step compiles the plugin, installs it into MySQL’s plugin directory, and registers all functions:

```bash
./script/build.sh
```

### 3. Link OpenFHE Shared Libraries

If the system cannot find `libOPENFHE*.so`, run:

```bash
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/openfhe.conf
sudo ldconfig
```

### 4. Run the Test Suite

```bash
./script/test.sh
```

---

## ✅ UDFs and Features

| Function | Description |
|----------|-------------|
| `HERMES_ENC_SINGULAR_BFV(val)` | Encrypt a plaintext integer into a BFV ciphertext (base64) |
| `HERMES_DEC_SINGULAR_BFV(ciphertext)` | Decrypt base64-encoded ciphertext and return plaintext |
| `HERMES_SUM_BFV(ciphertext)` | Aggregate ciphertexts over SQL groups and return decrypted sum |
| `HERMES_MUL_SCALAR_BFV(ciphertext, scalar)` | Multiply ciphertext by a plaintext scalar |
| `HERMES_MUL_BFV(ciphertext1, ciphertext2)` | Multiply two ciphertexts homomorphically |

Fully compatible with standard SQL pipelines such as `SELECT`, `GROUP BY`, and joins.

---

## 🧠 Tips & Troubleshooting

### Valid Plaintext Moduli

BFV requires the plaintext modulus $p$ to satisfy:

$$
(p - 1) \bmod m = 0
$$

Where $m$ is the cyclotomic ring dimension (default: $2^{14} = 16384$).

✅ Valid: `268369921`  
❌ Invalid: `131101` (leads to `SetParams_2n()` / `RootOfUnity()` errors)

To search for valid $p$:

```bash
python3 scripts/find_valid_moduli.py --ring-dim 16384 --min 100000000 --max 300000000
```

### Diagnosing Crashes

If MySQL crashes during plugin execution, check logs:

```bash
sudo tail -n 100 /var/log/mysql/error.log
```

Typical causes:
- Invalid modulus
- Memory exhaustion
- Mislinked plugin

---

## 👤 Contact

Dr. Dongfang Zhao  
HPDIC Lab, University of Washington  
📧 dzhao@cs.washington.edu
