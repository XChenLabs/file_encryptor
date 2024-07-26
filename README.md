# file_encryptor
A simple file encryptor in Rust (password-based-encryption using argon2id, aes-gcm)

usage: file_encryptor enc/dec input_file output_file

# basic design
A master key is derived from user's password and randomly generated salt using secure argon2id password hashing algorithm.

A randomly generated data_key is used to encrypt the input file using aes-gcm authenticated encryption algorithm.

The data_key itself is encrypted using master key and aes-gcm algorithm and stored with the encrypted file.

The data structure of an encrypted file:
1. salt: 16 bytes
2. nonce1: 12 bytes
3. encrypted data_key: 32 bytes
4. nonce2: 12 bytes
5. encrypted file data
