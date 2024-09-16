#!/bin/bash

# Set the base directory
BASE_DIR="$HOME/code/WatchfulDeerRust/watchful_deer"
# Check if the correct number of arguments is provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 -e|-d passphrase"
    exit 1
fi
option=$1
passphrase=$2
input_file="$BASE_DIR/steg"
output_file="$BASE_DIR/steg.enc"

case $option in
    -e)
        # Encrypt the file
        if [ -f "$output_file" ]; then
            openssl enc -aes-256-cbc -salt -in "$output_file" -out "$input_file" -pass pass:"$passphrase" -pbkdf2
            if [ $? -eq 0 ]; then
                echo "File encrypted successfully."
                rm "$output_file"  # Remove the plaintext file
            else
                echo "Failed to encrypt the file."
            fi
        else
            echo "No file named $output_file found to encrypt."
        fi
        ;;
    -d)
        # Decrypt the file
        if [ -f "$input_file" ]; then
            openssl enc -d -aes-256-cbc -in "$input_file" -out "$output_file" -pass pass:"$passphrase" -pbkdf2
            if [ $? -eq 0 ]; then
                cat "$output_file"  # Output the decrypted password
                rm "$output_file"
                exit 0
            else
                echo "Failed to decrypt the file."
                exit 1
            fi
        else
            echo "No file named $input_file found to decrypt."
            exit 1
        fi
        ;;
    *)
        echo "Invalid option. Use -e to encrypt or -d to decrypt."
        exit 1
        ;;
esac

