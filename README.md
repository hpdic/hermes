# Hermes: MySQL Plugin for Homomorphic Encryption

**Hermes** stands for **Homomorphic Encryption for Relational MySQL Engine Support**.  
The system embeds homomorphic encryption directly into MySQL via native UDF plugins, enabling SQL users to perform secure computation on encrypted data without modifying their queries.

The name is also inspired by *Hermes*, the Greek god of communication, reflecting the system's goal of secure, efficient, and seamless delivery of encrypted information.

---

## 🔐 Key Features

Hermes exposes the following homomorphic encryption UDFs as native SQL functions. Each UDF is implemented in a corresponding `.so` plugin module:

| Function | Description | Plugin Source |
|----------|-------------|----------------|
| `HERMES_ENC_SINGULAR_BFV(val)` | Encrypt a plaintext integer into a BFV ciphertext (base64) | `singular/udf.cpp` |
| `HERMES_DEC_SINGULAR_BFV(ciphertext)` | Decrypt base64-encoded ciphertext and return plaintext | `singular/udf.cpp` |
| `HERMES_SUM_BFV(ciphertext)` | Aggregate ciphertexts over SQL groups and return decrypted sum | `singular/udf.cpp` |
| `HERMES_MUL_SCALAR_BFV(ciphertext, scalar)` | Multiply ciphertext by a plaintext scalar | `singular/udf.cpp` |
| `HERMES_MUL_BFV(ciphertext1, ciphertext2)` | Multiply two ciphertexts homomorphically | `singular/udf.cpp` |
| `HERMES_PACK_CONVERT(val)` | Pack values into a ciphertext vector (aggregate) | `pack/packing.cpp` |
| `HERMES_DEC_VECTOR_BFV(ct)` | Decrypt and return vector plaintext as CSV | `pack/packing.cpp` |
| `HERMES_PACK_GROUP_SUM(val)` | Compute encrypted scalar sum within group (aggregate) | `pack/packsum.cpp` |
| `HERMES_PACK_GLOBAL_SUM(ct)` | Sum local encrypted group aggregates homomorphically | `pack/packsum.cpp` |
| `HERMES_DEC_SINGULAR(ct)` | Decrypt scalar ciphertext (internal SO-safe only) | `pack/packsum.cpp` |

All functions use the **BFV** scheme via [OpenFHE](https://github.com/openfheorg/openfhe-development) and are compatible with standard SQL operators such as `SELECT`, `GROUP BY`, and `CAST`.

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