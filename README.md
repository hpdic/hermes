# Hermes: MySQL Plugin for Homomorphic Encryption

**Hermes** stands for **Homomorphic Encryption for Relational MySQL Engine Support**.  
The system embeds homomorphic encryption directly into MySQL via native UDF plugins, enabling SQL users to perform secure computation on encrypted data without modifying their queries.

The name is also inspired by *Hermes*, the Greek god of communication, reflecting the system's goal of secure, efficient, and seamless delivery of encrypted information.

---

## 🔐 Key Features

Hermes supports the following homomorphic operations via SQL-native UDFs:

| Function | Description |
|----------|-------------|
| `HERMES_ENC_SINGULAR_BFV(val)` | Encrypts a plaintext integer into a BFV ciphertext (base64) |
| `HERMES_DEC_SINGULAR_BFV(ciphertext)` | Decrypts base64-encoded ciphertext back to an integer |
| `HERMES_SUM_BFV(ciphertext)` | Aggregates ciphertexts over SQL groups (homomorphic addition) |
| `HERMES_MUL_SCALAR_BFV(ciphertext, scalar)` | Multiplies ciphertext by a plaintext scalar |
| `HERMES_MUL_BFV(ciphertext1, ciphertext2)` | Multiplies two ciphertexts homomorphically |
| `HERMES_PACK_CONVERT(values)` | Packs a group of integers into an encrypted vector |
| `HERMES_DEC_VECTOR_BFV(ciphertext)` | Decrypts a packed ciphertext and returns the vector |
| `HERMES_PACK_GROUP_SUM(values)` | Computes encrypted scalar sum per group |
| `HERMES_PACK_GLOBAL_SUM(ciphertexts)` | Computes global encrypted sum across groups |

All operations are **BFV-based** and compatible with SQL pipelines (e.g., `GROUP BY`, `JOIN`, `CAST`).

---

## 🚀 Quick Start

Build and test with:

```bash
./script/build.sh               # Compile and register plugins
./script/run_crypto.sh          # Run primitive FHE operations
./script/run_singular.sh        # Run single-tuple demo
./script/run_pack.sh            # Run packed vector + summation demo
```

For full installation instructions, see [INSTALL.md](./INSTALL.md).

---

## 📦 Design Philosophy

Hermes is designed to:

- **Minimize system intrusion**: implemented entirely as MySQL UDFs.
- **Enable modular deployment**: each homomorphic operation is a plugin.
- **Preserve SQL compatibility**: no schema rewrites or query rewriting.
- **Support secure processing**: all ciphertexts remain encrypted in transit and storage.

---

## 📬 Contact

(c) 2025, HPDIC Lab, University of Washington  
Author: **Dr. Dongfang Zhao**  
📧 Email: <dzhao@cs.washington.edu>

---

## 📄 License

This project is released under the [Apache License 2.0](LICENSE).