rsa
===

Python RSA public-key encryption system

## Files ##
        rsa.py - application for generating rsa keys, encrypting data, and decrypting data
        bodineac_keys - pickled file containing all necessary encryption/decryption meta data ( my rsa keys )
        plaintext - orignial plaintext file that we were given
        ciphertext - result of encrypting plaintext file
        decrypted - result of decrypting ciphertext file

## Usage ##
        to generate rsa keys: python rsa.py init <keys_filename> <prime_bitlength>
                ex. python rsa.py init bodineac_keys 512
        to encrypt data: python rsa.py encrypt <keys_filename> <plaintext_filename> <ciphertext_filename>
                ex. python rsa.py encrypt bodineac_keys plaintext ciphertext
        to decrypt data: python rsa.py decrypt <keys_filename> <ciphertext_filename> <decrypted_filename>
                ex. python rsa.py decrypt bodineac_keys ciphertext decrypted
