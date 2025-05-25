# Hermes: Encrypted Query Processing via MySQL + OpenFHE

Hermes is a homomorphic encryption plugin for MySQL using the OpenFHE library (BFV scheme). It provides compile-time encryption, ciphertext storage, decryption, and aggregation—all as native SQL functions.

---

## 📦 System Requirements

Ensure the following dependencies are installed:

### Required Packages

- **MySQL Server (>= 8.0)**
- **OpenFHE (>= v1.1.1)** compiled with BFV support
- **CMake (>= 3.10)**
- **g++ (>= 9.4)** or any C++17-compatible compiler
- **libmysqlclient-dev**
- **Python 3** (for helper scripts)

Install core packages via:

```bash
sudo apt update
sudo apt install mysql-server libmysqlclient-dev cmake g++ build-essential python3
```

---

## 🔁 OpenFHE Compatibility

All testing and plugin development was performed using this fork:

👉 <https://github.com/hpdic/openfhe-development>

⚠️ **We do not guarantee compatibility** with the upstream OpenFHE releases due to possible API divergence.

---

## 🔧 Installation Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/hpdic/hermes.git
cd hermes
```

### 2. Build and Register the Plugin

This will compile the plugin, copy it into MySQL’s plugin directory, and register all UDFs:

```bash
./script/build.sh
```

### 3. Ensure OpenFHE Shared Libraries Are Visible

If your system cannot find OpenFHE's shared libraries (e.g., `libOPENFHEpke.so`), add this path to the system linker:

```bash
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/openfhe.conf
sudo ldconfig
```

### 4. Test the Plugin

```bash
./script/test.sh
```

---

## 🧠 Tips & Troubleshooting

### Picking a Valid BFV Plaintext Modulus

OpenFHE requires the plaintext modulus $p$ to satisfy:

$$
\frac{p - 1}{m} \in \mathbb{Z}
$$

Where $m$ is the cyclotomic ring dimension (default: $2^{14} = 16384$).

✅ Valid example: `268369921`  
❌ Invalid example: `131101` (will crash with `SetParams_2n()` or `RootOfUnity()`)

A helper script is provided to scan for suitable primes that satisfy:

```bash
(p - 1) % m == 0
```

Run it via:

```bash
python3 scripts/find_valid_moduli.py --ring-dim 16384 --min 100000000 --max 300000000
```

### Diagnosing MySQL Plugin Crashes

If MySQL crashes during an encrypted query, check:

```bash
sudo tail -n 100 /var/log/mysql/error.log
```

Common crash reasons:
- Incompatible BFV modulus
- Memory limits exceeded
- Improper plugin linkage

---

## ✅ Features Tested

- `HERMES_ENC_SINGULAR_BFV`: Encrypt a plaintext integer as BFV ciphertext (base64)
- `HERMES_DEC_SINGULAR_BFV`: Decrypt the ciphertext and return plaintext
- `HERMES_SUM_BFV`: Aggregate encrypted values and return the decrypted sum
- Full compatibility with `GROUP BY` SQL clause

---

## 👤 Contact

Dr. Dongfang Zhao  
HPDIC Lab, University of Washington  
Email: <dzhao@cs.washington.edu>