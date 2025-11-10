#!/bin/bash
set -e

# --- Configuration ---
# WARNING: Do not use hardcoded passwords in production.
# This is suitable for local development setup only.

# 1. Set your desired *new* root password
ROOT_PASS="root" # <-- !! CHANGE THIS !!

# 2. The FHE user you want to create
USER_NAME="hpdic"
USER_PASS="hpdic2023"
USER_HOST="localhost"

echo "--- MySQL Automated Setup Script ---"
echo "This script will set a password for 'root'@'localhost' and create the '${USER_NAME}' user."
echo "It assumes you can log in via 'sudo mysql' without a password (e.g., using auth_socket)."
echo "Press Enter to continue, or Ctrl+C to cancel..."
read

# --- Execute Setup ---
# We use a "here document" (<<EOF) to pass a series of SQL commands
# to the 'mysql' client, run as 'sudo'.

sudo mysql <<MYSQL_SCRIPT
-- 1. Change root user authentication to password and set the password
-- THIS IS THE CRITICAL FIX: We must specify 'IDENTIFIED WITH'
ALTER USER 'root'@'${USER_HOST}' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASS}';

-- 2. Create your hpdic user (if they don't already exist)
-- We do the same for the new user to ensure password login works
CREATE USER IF NOT EXISTS '${USER_NAME}'@'${USER_HOST}' IDENTIFIED WITH 'mysql_native_password' BY '${USER_PASS}';

-- 3. (Optional) In case the user already existed, force update their plugin and password
ALTER USER '${USER_NAME}'@'${USER_HOST}' IDENTIFIED WITH 'mysql_native_password' BY '${USER_PASS}';

-- 4. Grant the hpdic user all privileges (for development)
GRANT ALL PRIVILEGES ON *.* TO '${USER_NAME}'@'${USER_HOST}' WITH GRANT OPTION;

-- 5. Apply all changes immediately
FLUSH PRIVILEGES;

SELECT 'MySQL setup complete.' AS 'Status';
MYSQL_SCRIPT

echo "--- Setup Complete ---"
echo "Root password has been set."
echo "User '${USER_NAME}' is ready."
echo ""

# --- Test Connections ---
# Now we attempt to connect using the new credentials
echo "Testing 'root' connection..."
if mysql -u root -p${ROOT_PASS} -e "SHOW DATABASES;" > /dev/null 2>&1; then
    echo "Root login successful."
else
    echo "Root login FAILED! Please check the script or password."
    exit 1
fi

echo "Testing '${USER_NAME}' connection..."
if mysql -u ${USER_NAME} -p${USER_PASS} -e "SHOW DATABASES;" > /dev/null 2>&1; then
    echo "${USER_NAME} login successful."
else
    echo "${USER_NAME} login FAILED! Please check the script or password."
    exit 1
fi

echo "--- Automation Succeeded ---"