# Hermes: Encrypted Query Processing via MySQL + OpenFHE

Hermes is a homomorphic encryption plugin for MySQL using the OpenFHE library (BFV scheme). It provides compile-time encryption, ciphertext storage, decryption, and aggregation—all as native SQL functions.

## 📦 System Requirements

Before proceeding, ensure the following dependencies are installed:

### Required Packages

- **MySQL Server (>= 8.0)**
- **OpenFHE (>= v1.1.1)** compiled with BFV support
- **CMake (>= 3.10)**
- **g++ (>= 9.4)** or any C++17-compatible compiler
- **libmysqlclient-dev**

You can install required system packages via:

```bash
sudo apt update
sudo apt install mysql-server libmysqlclient-dev cmake g++ build-essential
```

### OpenFHE Note

All testing and plugin development was performed against the HPDIC-maintained OpenFHE fork:

👉 <https://github.com/hpdic/openfhe-development>

If you choose to use the official OpenFHE release at <https://github.com/openfheorg/openfhe-development>, **we do not guarantee compatibility** due to potential API or build differences.

## 🔧 Installation Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/hpdic/hermes.git
cd hermes
```

### 2. Build and Register the Plugin

Run the following script to compile Hermes, install the plugin into MySQL, and register all UDFs:

```bash
./script/build.sh
```

### 3. Ensure OpenFHE Libraries Are Discoverable

If your system cannot find OpenFHE's shared libraries (e.g., `libOPENFHEpke.so`), add this path to the system linker:

```bash
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/openfhe.conf
sudo ldconfig
```

This makes `/usr/local/lib` visible to the dynamic linker used by MySQL.

### 4. Test the Plugin

This will restart MySQL, reinitialize the test database, and run example encrypted queries:

```bash
./script/test.sh
```

## ✅ Features Tested

- `HERMES_ENC_SINGULAR_BFV`: Encrypt a plaintext integer as BFV ciphertext (base64).
- `HERMES_DEC_SINGULAR_BFV`: Decrypt the ciphertext and return plaintext.
- `HERMES_SUM_BFV`: Aggregate encrypted values and return the decrypted sum.
- Full compatibility with `GROUP BY` SQL clause.

## 👤 Contact

Dr. Dongfang Zhao  
HPDIC Lab, University of Washington  
Email: <dzhao@cs.washington.edu>
