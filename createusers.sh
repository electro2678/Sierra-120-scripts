#!/bin/bash

# Script to create admin accounts from a CSV file.
# Author: Jason Schlager - Help with gemma3 AI 20250513
# Requires:
# - A CSV file named 'users.csv' with 2 columns 
# example
# no header just 2 columns 
#
# username,password
# username2,password
#
# - sudo privileges to create user accounts
#
# Usage: ./create_admin_accounts.sh users.csv

# Check if the CSV file exists
if [ ! -f "users.csv" ]; then
  echo "Error: users.csv not found."
  exit 1
fi

# Check if the CSV file is readable
if [ ! -r "users.csv" ]; then
  echo "Error: users.csv is not readable."
  exit 1
fi

# Loop through the CSV file
while IFS=',' read -r user_id password; do
  # Sanitize input (important for security - prevents command injection)
  user_id=$(echo "$user_id" | tr -d ' ') # Remove spaces from user_id
  password=$(echo "$password" | tr -d ' ') # Remove spaces from password

  # Create the user account with sudo privileges
  sudo useradd "$user_id"
  if [ $? -ne 0 ]; then
    echo "Error: Failed to create user account for $user_id"
    continue # Skip to the next user
  fi

  # Set the password (use a secure method, like chpasswd - avoid echoing passwords in plain text)
  echo "$user_id:$password" | sudo chpasswd

  if [ $? -ne 0 ]; then
    echo "Error: Failed to set password for $user_id"
    # Optionally, delete the user if password setting fails.  This prevents a partially created account.
    sudo userdel "$user_id"
    continue
  fi

  # Add the user to the sudo group
  sudo usermod -a -G sudo "$user_id"

  if [ $? -ne 0 ]; then
    echo "Error: Failed to add $user_id to sudo group"
    # Optionally, delete the user if adding to sudo group fails
    sudo userdel "$user_id"
    continue
  fi

  echo "Admin account created successfully for $user_id"
done < "users.csv"

echo "Finished creating admin accounts."

exit 0
