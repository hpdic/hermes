# Update on 1/18/2026, for Chameleon Cloud

## Install OpenFHE
```bash
cd
git clone https://github.com/hpdic/cnpy.git
cd ~/cnpy
mkdir build && cd build
cmake ..
make -j
sudo make install

cd
git clone git@github.com:hpdic/openfhe-development.git
cd ~/openfhe-development
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS_DEBUG="-g -O0" -DBUILD_UNITTESTS=OFF ..
make -j
sudo make install
~/openfhe-development/build/bin/examples/pke/simple-integers
```

## Install MySQL
```bash
cd
sudo apt install mysql-server -y
sudo apt install libmysqlclient-dev -y
sudo mysql_secure_installation
# Answer the interactive questions above
```

## Install Hermes
```bash
cd
git clone git@github.com:hpdic/hermes.git
cd ~/Hermes/
bash ./scripts/setup_mysql.sh
# Press Enter to confirm the account creations

sudo EDITOR=vim systemctl edit mysql
# Add the following two lines to the above file (allowing MySQL to access external libs):
# [Service]
# Environment="LD_LIBRARY_PATH=/usr/lib/mysql/plugin:$LD_LIBRARY_PATH"

sudo systemctl daemon-reload
sudo systemctl restart mysql
sudo cp ~/openfhe-development/build/lib/libOPENFHE* /usr/lib/mysql/plugin/.
cd ~/Hermes
bash ./scripts/build.sh

sudo vim /etc/apparmor.d/usr.sbin.mysqld
# To allow MySQL to access the keys in the temp directory,
# add the following two lines at the end of the file (before "}"):
# /tmp/hermes/ r,
# /tmp/hermes/* r,

sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.mysqld
sudo systemctl restart mysql
```

## Quick Test
```bash
cd ~/Hermes
./scripts/run_crypto.sh
./scripts/run_singular.sh
./scripts/run_pack.sh
```

## Example Output
```bash
cc@rtx6000:~/Hermes$ cd ~/Hermes
./scripts/run_crypto.sh
./scripts/run_singular.sh
./scripts/run_pack.sh
[*] Running crypto module unit tests...

[+] Running test_eval...
[test_eval] Initializing BFV context...
[test_eval] Encrypting a = 7, b = 5
[test_eval] a + b = 12
[test_eval] a * b = 35
[test_eval] a + 3 = 10
[test_eval] b * 4 = 20
[✓] All evaluation tests passed.

[+] Running test_serialize...
[1] Context and keys generated.
    > Wrote 394125 bytes to tmp/publicKey.txt
    > Wrote 197390 bytes to tmp/secretKey.txt
[2] Keys serialized.
[3] Encrypting plaintext: 100
    > Wrote 394169 bytes to tmp/ciphertext.txt
[3] Ciphertext serialized.
    > Read 394125 bytes from tmp/publicKey.txt
    > Read 197390 bytes from tmp/secretKey.txt
    > Read 394169 bytes from tmp/ciphertext.txt
[4] Context and keys deserialized.
[5] Decrypted plaintext: 100
[✓] Ciphertext roundtrip test passed.

[✓] All crypto unit tests passed.
[*] Running encrypted SQL tests...

[1] Setting up test database and base employee table...

[2] Encrypting salary values using HERMES_ENC_SINGULAR_BFV...

[3] Previewing ciphertext prefix (first 8 chars)...
id      name    department      salary_enc_preview
1       Alice   HR      AQAAAEAB
2       Bob     HR      AQAAAEAB
3       Carol   ENG     AQAAAEAB
4       Dave    ENG     AQAAAEAB

[4] Decrypting encrypted salaries using HERMES_DEC_SINGULAR_BFV...
id      name    department      salary_plain
1       Alice   HR      5200
2       Bob     HR      4800
3       Carol   ENG     6000
4       Dave    ENG     5900

[5] Performing homomorphic sum by department using HERMES_SUM_BFV...
department      total_salary
ENG     11900
HR      10000

[6] Adding encrypted months column (12 months/year)...

[7] Computing annual salary = salary × months (homomorphic mul)...
name    annual_salary
Alice   62400
Bob     57600
Carol   72000
Dave    70800

[✓] Test completed successfully.

[HERMES-TEST] === NEW HERMES PACK TEST @ 2026-01-19 00:42:07 ===
[+] Created table 'employees'.
[+] Inserted sample employee records.
[*] Packing salaries per department...
+------+-------------------+
| dept | encrypted_preview |
+------+-------------------+
|    1 | 41514141          |
|    2 | 41514141          |
+------+-------------------+
[+] Inserted packed ciphertexts into 'packed_salaries' with slot counts.
[*] Decrypting packed ciphertexts...
+------+------------+----------------+
| dept | slot_count | salary_vector  |
+------+------------+----------------+
|    1 |          3 | 1000,2000,1500 |
|    2 |          2 | 3000,2500      |
+------+------------+----------------+
[*] Adding 'local_sum_ct' column to packed_salaries...
[*] Computing and storing encrypted local sum for each group...
[+] Encrypted local sums written into 'packed_salaries.local_sum_ct'.
[*] Decrypting local group sums...
+------+------------+----------------+-----------+
| dept | slot_count | salary_vector  | local_sum |
+------+------------+----------------+-----------+
|    1 |          3 | 1000,2000,1500 | 4500      |
|    2 |          2 | 3000,2500      | 5500      |
+------+------------+----------------+-----------+
[*] Computing global sum (homomorphic sum of local group sums)...
[+] Computed global ciphertext sum.
[*] Decrypting global sum...
+------------+
| global_sum |
+------------+
| 10000      |
+------------+
[*] Testing HERMES_PACK_ADD ...
+------+------------+---------------------+-------------+
| dept | slot_count | updated_vector      | updated_sum |
+------+------------+---------------------+-------------+
|    1 |          4 | 1000,2000,1500,9999 | 14499       |
+------+------------+---------------------+-------------+
[*] Testing HERMES_PACK_RMV ...
+------+------------+----------------+-------------+
| dept | slot_count | updated_vector | updated_sum |
+------+------------+----------------+-------------+
|    1 |          3 | 1000,9999,1500 | 12499       |
+------+------------+----------------+-------------+
cc@rtx6000:~/Hermes$ 
```

## How to Recompile and Debug
This is how I debug. You want to have two terminals. Maybe the upper terminal is to test your SQL statements like this
```bash
cc@rtx6000:~/Hermes$ mysql -u hpdic -phpdic2023 -e "use hpdic_db; select id, salary, hermes_enc_singular_bfv(salary) from employee_grouped limit 1;"
```
And the lower one is to recompile the changed code with error messages (e.g., `std::cerr << __FILE__ << ":" __LINE__ << std::endl;`) and check the MySQL log:
```bash
cc@rtx6000:~/Hermes$ ./scripts/build.sh 
cc@rtx6000:~/Hermes$ sudo tail /var/log/mysql/error.log -n10
```

## VS Code
If you use VS Code, you might need to manually add the following to help VS Code find the MySQL headers:
```bash
/home/cc/Hermes/src
```

# Update on 11/10/2025, for CloudLab, assuming OpenFHE is installed: https://github.com/hpdic/openfhe-development

## MySQL
```bash
sudo apt install mysql-server -y
sudo apt install libmysqlclient-dev -y
sudo mysql_secure_installation
```
Answer the interactive questions above (e.g., just say No to all of them), then:
```bash
cd
git clone git@github.com:hpdic/hermes.git
cd ~/hermes/
bash ./scripts/setup_mysql.sh
sudo EDITOR=vim systemctl edit mysql
```
Add the following to the above file (this would allow MySQL to access external libs):
```bash
[Service]
Environment="LD_LIBRARY_PATH=/usr/lib/mysql/plugin:$LD_LIBRARY_PATH"
```
Then run:
```bash
sudo systemctl daemon-reload
sudo systemctl restart mysql
sudo cp ~/openfhe-development/build/lib/libOPENFHE* /usr/lib/mysql/plugin/.
cd ~/Hermes
bash ./scripts/build.sh
```

## AppArmor
Depending on your Linux/MySQL version, Hermes may not be able to access the default directory of keys, i.e., /tmp/hermes/. When this happens, you will see a lot of NULL values in the test script, which is likely due to the denied access to the keys stored in the temporary directory. To fix this:
```bash
sudo vim /etc/apparmor.d/usr.sbin.mysqld
```
Add the following two lines at the end of the file (before "}"):
```bash
# Allow MySQL to access the keys in the temp directory
  /tmp/hermes/ r,
  /tmp/hermes/* r,
```
Then reset MySQL: 
```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.mysqld
sudo systemctl restart mysql
```

## Run Tests
Now you should be able to run the test scripts:
```bash
cd ~/hermes
./scripts/run_crypto.sh
./scripts/run_singular.sh
./scripts/run_pack.sh
```
Example output of the above test scripts can be found by
```bash
cat ~/hermes/scripts/example_output/*
```

## Debug
This is how I debug. You want to have two terminals. Maybe the upper terminal is to test your SQL statements like this
```bash
donzhao@node0:~/hermes$ mysql -u hpdic -e "use hpdic_db; select id, salary, hermes_enc_singular_bfv(salary) from employee_grouped;"
```
And the lower one is to recompile the changed code with error messages (e.g., `std::cerr << __FILE__ << ":" __LINE__ << std::endl;`) and check the MySQL log:
```bash
donzhao@node0:~/hermes$ ./scripts/build.sh 
donzhao@node0:~/hermes$ sudo tail /var/log/mysql/error.log -n10
```

## VS Code
If you use VS Code, you might need to manually add the following to help VS Code find the MySQL headers:
```
/usr/include/mysql/**
```

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

OpenFHE contexts are not safely portable across `.so` boundaries. Even with identical parameters, BFV `CryptoContext` objects created in different shared libraries are structurally incompatible due to crytpographic requirements, e.g., different (pseudo)random seeds.

To ensure encryption and decryption succeed:

✅ Pair encryption and decryption UDFs **WITHIN** the **same `.so`**  
❌ Avoid passing ciphertexts between plugins; it won't work

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

