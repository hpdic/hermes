# Hermes: MySQL Plugin for Homomorphic Encryption

Hermes is a research prototype that integrates homomorphic encryption into SQL
via MySQL UDF (User-Defined Function) plugins using the OpenFHE library. It currently
supports compile-time encryption, runtime decryption, and encrypted aggregation using
the BFV scheme in single-slot mode.

## 🔍 Key Features

- `HERMES_ENC_SINGULAR_BFV`: Encrypt a plaintext integer into a base64-encoded BFV ciphertext.
- `HERMES_DEC_SINGULAR_BFV`: Decrypt a base64-encoded ciphertext and return the original integer.
- `HERMES_SUM_BFV`: Perform homomorphic summation over encrypted columns in SQL (supports `GROUP BY`).

## 🚀 Quick Start

To compile, deploy, and run tests:

```bash
./script/build.sh
./script/test.sh
```

For installation instructions, see [INSTALL.md](./INSTALL.md).

## 🧪 Demo

See `script/test.sh` for an end-to-end demonstration of encryption, decryption, and group-by aggregation in MySQL using homomorphic encryption.

## 📬 Contact

(c) 2025, HPDIC Lab, University of Washington  
Author: Dr. Dongfang Zhao  
Email: <dzhao@cs.washington.edu>

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE).
