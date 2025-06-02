# Hermes: Homomorphic Encryption Plugin for MySQL

Hermes is a MySQL plugin powered by OpenFHE (using the BFV scheme) that enables native SQL-compatible encrypted computation. It supports scalar encryption, packed vector encoding, encrypted aggregation, slot-wise updates, and group-wise secure computation.

---

## 📦 System Requirements

Ensure the following packages are installed:

- **MySQL Server (>= 8.0)**
- **OpenFHE (>= v1.2.4)** with BFV support
- **CMake (>= 3.10)**
- **g++ (>= 9.4)** or any C++17-compliant compiler
- **libmysqlclient-dev**
- **Python 3** (for helper scripts)

Install via:

```bash
sudo apt update
sudo apt install mysql-server libmysqlclient-dev cmake g++ build-essential python3
```

---

## 🔁 OpenFHE Compatibility

Tested using the following OpenFHE fork:

👉 https://github.com/hpdic/openfhe-development

⚠️ Compatibility with upstream OpenFHE is **not guaranteed** due to API and serialization format differences.

---

## ⚠️ CryptoContext Isolation Warning

OpenFHE contexts are not safely portable across `.so` boundaries. Even with identical parameters, BFV `CryptoContext` objects created in different shared libraries may be structurally incompatible.

To ensure encryption and decryption succeed:

✅ Pair encryption and decryption UDFs within the **same `.so`**  
❌ Avoid passing ciphertexts between plugins

---

## 🔧 Installation

### 1. Clone Repository

```bash
git clone https://github.com/hpdic/hermes.git
cd hermes
```

### 2. Build and Register All Plugins

Run:

```bash
./script/build.sh
```

This will:
- Compile all plugin sources
- Install shared libraries to `/usr/lib/mysql/plugin/`
- Restart MySQL
- Register all UDFs (scalar and aggregate)
- Generate BFV key pair under `/tmp/hermes/`

### 3. Link OpenFHE Libraries

If `libOPENFHE*.so` cannot be found at runtime:

```bash
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/openfhe.conf
sudo ldconfig
```

---

## ✅ UDF Overview

| Function Name | Type | Description |
|---------------|------|-------------|
| `HERMES_ENC_SINGULAR_BFV(val)` | Scalar | Encrypts integer `val` into slot[0] of a packed BFV ciphertext |
| `HERMES_DEC_SINGULAR_BFV(ct)` | Scalar | Decrypts a base64 ciphertext and returns plaintext at slot[0] |
| `HERMES_SUM_BFV(val)` | Aggregate | Homomorphic summation of group values (encrypts result) |
| `HERMES_MUL_BFV(ct1, ct2)` | Scalar | Homomorphic multiplication of two ciphertexts |
| `HERMES_MUL_SCALAR_BFV(ct, scalar)` | Scalar | Multiply ciphertext by plaintext scalar |
| `HERMES_PACK_CONVERT(val)` | Aggregate | Packs grouped values into a ciphertext vector |
| `HERMES_DEC_VECTOR(ct, k)` | Scalar | Decrypts and prints vector of `k` slots |
| `HERMES_PACK_GROUP_SUM(val)` | Aggregate | Computes groupwise encrypted sum |
| `HERMES_PACK_GLOBAL_SUM(ct)` | Aggregate | Sums multiple encrypted group aggregates |
| `HERMES_ENC_SINGULAR(val)` | Scalar | Internal-use secure scalar encryption (BFV packed slot[0]) |
| `HERMES_DEC_SINGULAR(ct)` | Scalar | Internal-use decryption of slot[0] |
| `HERMES_PACK_ADD(ct, val, idx)` | Scalar | Inserts `val` into `ct` at slot `idx` homomorphically |
| `HERMES_PACK_RMV(ct, idx, k)` | Scalar | Removes slot `idx` by compacting last slot in k-length vector |
| `HERMES_SUM_CIPHERS(ct1, ct2)` | Scalar | Homomorphic addition of two ciphertexts |

---

## 🧪 Run End-to-End Test

Use the test script:

```bash
./script/run_pack.sh
```

This runs a full SQL workflow using:

- Encrypted packing
- Encrypted group aggregation
- Encrypted updates and slot removal
- Final global sum verification

---

## 🔍 Debugging Tips

### Valid Modulus

BFV requires plaintext modulus $p$ such that $(p - 1) \mod m = 0$.

Default ring dimension: $m = 16384$  
✅ Valid: `268369921`  
❌ Invalid: `131101` (throws RootOfUnity errors)

Search for a valid modulus via:

```bash
python3 scripts/find_valid_moduli.py --ring-dim 16384 --min 100000000 --max 300000000
```

### Crash Recovery

```bash
sudo tail -n 100 /var/log/mysql/error.log
```

Common causes:

- Context mismatch across plugins
- Invalid ciphertext
- Incorrect plaintext modulus
- Memory overflow

---

## 👤 Contact

**Dr. Dongfang Zhao**  
HPDIC Lab, University of Washington  
📧 dzhao@cs.washington.edu

