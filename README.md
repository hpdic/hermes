# Hermes: MySQL Plugin for Homomorphic Encryption

The name **Hermes** stands for **Homomorphic Encryption for Relational MySQL Engine Support**. The system integrates encrypted computation directly into SQL workflows via native MySQL UDF plugins. The name is also inspired by Hermes—the Greek god of communication and messenger of the gods—symbolizing secure, efficient delivery of information across domains.

---

## 🔍 Key Features

- `HERMES_ENC_SINGULAR_BFV`: Encrypts a plaintext integer into a base64-encoded BFV ciphertext.
- `HERMES_DEC_SINGULAR_BFV`: Decrypts a base64 ciphertext and returns the original integer.
- `HERMES_SUM_BFV`: Aggregates encrypted values homomorphically across rows (compatible with `GROUP BY`).
- `HERMES_MUL_BFV`: Homomorphic ciphertext × ciphertext multiplication.
- `HERMES_MUL_SCALAR_BFV`: Homomorphic scalar multiplication (ciphertext × plaintext integer).

---

## 🚀 Quick Start

To build and run tests:

```bash
./script/build.sh
./script/test.sh
```

For detailed setup and requirements, see [INSTALL.md](./INSTALL.md).

---

## 🧪 Demo Workflow

The script `script/test.sh` performs:

1. Sample data creation in MySQL.
2. Homomorphic encryption of salary values using BFV.
3. Decryption verification using SQL.
4. Grouped summation using `HERMES_SUM_BFV`.
5. Multiplication of encrypted salaries by plaintext scalars (e.g., bonuses).
6. Full ciphertext × ciphertext multiplication (e.g., salary × months).

---

## 📬 Contact

(c) 2025, HPDIC Lab, University of Washington  
Author: Dr. Dongfang Zhao  
Email: <dzhao@cs.washington.edu>

---

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE).
