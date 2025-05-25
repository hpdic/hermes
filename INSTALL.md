# Hermes: Encrypted Query Processing via MySQL + OpenFHE

Hermes is a homomorphic encryption plugin for MySQL using the OpenFHE library (BFV scheme). It provides compile-time encryption, ciphertext storage, decryption, and aggregation—all as native SQL functions.

## 🔧 Installation Instructions

### 1. Clone the repository

```bash
git clone https://github.com/hpdic/hermes.git
cd hermes
```

### 2. Build the Plugin

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### 3. Copy Plugin to MySQL

```bash
sudo cp libhermes_udf.so /usr/lib/mysql/plugin/
```

### 4. Ensure MySQL can see OpenFHE libraries

Edit or create this file:

```bash
sudo mkdir -p /etc/systemd/system/mysql.service.d/
sudo nano /etc/systemd/system/mysql.service.d/openfhe-env.conf
```

Add the line:

```
[Service]
Environment=LD_LIBRARY_PATH=/usr/lib/mysql/plugin
```

Then reload MySQL:

```bash
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl restart mysql
```

### 5. Run the Quick Test Script

```bash
chmod +x hermes_test_quick.sh
./hermes_test_quick.sh
```

## 📦 Features Tested

- `HERMES_ENC_SINGULAR_BFV`: Encrypt a plaintext integer as BFV ciphertext (base64).
- `HERMES_DEC_SINGULAR_BFV`: Decrypt the ciphertext and return plaintext.
- `HERMES_SUM_BFV`: Aggregate encrypted values and return the decrypted sum.
- Full compatibility with `GROUP BY` SQL clause.

## 👤 Contact

Dr. Dongfang Zhao  
HPDIC Lab, University of Washington  
Email: <dzhao@cs.washington.edu>
