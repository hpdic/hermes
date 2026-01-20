
# Hermes: MySQL Plugin for Homomorphic Encryption

**Hermes** stands for **Homomorphic Encryption for Relational MySQL Engine Support**.  
The system embeds homomorphic encryption directly into MySQL via native UDF plugins, enabling SQL users to perform secure computation on encrypted data without modifying their queries.

The name is also inspired by *Hermes*, the Greek god of communication, reflecting the system's goal of secure, efficient, and seamless delivery of encrypted information.

---

## Technical Documentation

* [Technical Report, Latest](paper/TR2026/hermes.pdf)
* [Preprint, June 2025](https://arxiv.org/abs/2506.03308)

## Installation

Please refer to the [INSTALL.md](INSTALL.md) file for detailed installation instructions.

## Academic Background

Hermes is part of an academic research initiative at the University of Washington, aiming to bridge modern cryptography and database systems. It is the first system to integrate fully homomorphic encryption (FHE) directly into a production-grade SQL engine, supporting vectorized queries with provable security guarantees.

## 🔐 Key Features

Hermes exposes the following homomorphic encryption UDFs as native SQL functions. Each UDF is implemented in a corresponding `.so` plugin module:

| UDF Function | Description | Source File |
|--------------|-------------|-------------|
| `HERMES_ENC_SINGULAR_BFV(val)` | Encrypt scalar integer (slot[0]) | `singular/udf.cpp` |
| `HERMES_DEC_SINGULAR_BFV(ct)` | Decrypt scalar ciphertext | `singular/udf.cpp` |
| `HERMES_SUM_BFV(ct)` | Aggregate ciphertexts homomorphically | `singular/udf.cpp` |
| `HERMES_MUL_BFV(ct1, ct2)` | Multiply two ciphertexts | `singular/udf.cpp` |
| `HERMES_PACK_CONVERT(val)` | Pack group values into vector ciphertext | `pack/packing.cpp` |
| `HERMES_DEC_VECTOR(ct)` | Decrypt packed vector into CSV | `pack/packing.cpp` |
| `HERMES_PACK_GROUP_SUM(val)` | Encrypt per-group sum | `pack/packsum.cpp` |
| `HERMES_PACK_GLOBAL_SUM(ct)` | Add all group ciphertexts | `pack/packsum.cpp` |
| `HERMES_ENC_SINGULAR(val)` | Encrypt scalar as BFV (internal SO-safe) | `pack/packsum.cpp` |
| `HERMES_DEC_SINGULAR(ct)` | Decrypt scalar (internal SO-safe) | `pack/packsum.cpp` |
| `HERMES_PACK_ADD(ct, val, idx)` | Insert value at given slot in packed ciphertext | `pack/packupdate.cpp` |
| `HERMES_PACK_RMV(ct, idx, k)` | Remove slot at index, compact vector | `pack/packupdate.cpp` |
| `HERMES_SUM_CIPHERS(ct1, ct2)` | EvalAdd of two ciphertexts | `pack/packupdate.cpp` |

All functions use the **BFV** scheme via [OpenFHE](https://github.com/openfheorg/openfhe-development) and are compatible with standard SQL operators such as `SELECT`, `GROUP BY`, and `CAST`.

---

## Quick Start

Build and test with:

```bash
./script/build.sh               # Compile and register plugins
./script/run_crypto.sh          # Run primitive FHE operations
./script/run_singular.sh        # Run single-tuple demo
./script/run_pack.sh            # Run packed vector + summation demo
```

---

## Reproducible Experiments

To run the benchmark suite:

```bash
./experiments/script/load_csv.sh        # Load data into MySQL
./experiments/script/convert_csv.sh     # Preprocess and assign group IDs
./experiments/script/run_all.sh         # Evaluate encryption, insert, delete
```

This will produce results in `./experiments/result/*.txt`, covering all three datasets: `covid19`, `bitcoin`, and `hg38`.

---

## Design Philosophy

Hermes is designed to:

- **Minimize system intrusion**: implemented entirely as MySQL loadable functions with C++.
- **Enable modular deployment**: each homomorphic operation is a plugin.
- **Preserve SQL compatibility**: no schema rewrites or query rewriting.
- **Support secure processing**: all ciphertexts remain encrypted in transit and storage.

---

## Contact

(c) 2025-2026, HPDIC Lab, https://hpdic.github.io  
Author: **Dongfang Zhao**  
Email: <dzhao@uw.edu>

---

## License
This project is released under the [Apache License 2.0](LICENSE).
