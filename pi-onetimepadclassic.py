#!/usr/bin/env/python3

import argparse
import re
from random import choice
from string import ascii_uppercase

def main():
    parser = argparse.ArgumentParser(
        description='One time pad encryption and decryption tool')
    subparsers = parser.add_subparsers(dest='action')
    parser_encrypt = subparsers.add_parser('encrypt',
                                           help='encrypt plaintext')
    group_encrypt_key = parser_encrypt.add_mutually_exclusive_group(required=True)
    group_encrypt_key.add_argument('-k', '--key',
                                   help='key for cipher')
    group_encrypt_key.add_argument('--gen-key', action='store_true',
                                   help='automatically generate a random key')
    parser_encrypt.add_argument('plaintext',
                                help='plaintext to encrypt')
    parser_decrypt = subparsers.add_parser('decrypt',
                                           help='decrypt ciphertext')
    parser_decrypt.add_argument('-k', '--key', required=True,
                                help='key for cipher')
    parser_decrypt.add_argument('ciphertext',
                                help='ciphertext to decrypt')
    args = parser.parse_args()
    print(vars(args))
    if args.action == "encrypt":
        encrypt(args)
    elif args.action == "decrypt":
        decrypt(args)
    else:
        parser.error("method required. (choose from 'encrypt', 'decrypt')")

def encrypt(args):
    print("encrypt")
    plaintext = args.plaintext.upper()
    print("plaintext: " + plaintext)
    plaintext_alpha = alphaonly(plaintext)
    if args.gen_key:
        key = ''.join(choice(ascii_uppercase) for _ in range(len(plaintext_alpha)))
    else:
        key = alphaonly(args.key.upper())
        if len(key) < len(plaintext_alpha):
            raise Exception("""The number of alphabetic characters in the key must
                            be longer than the number alphabetic charaters in the plaintext""")
    print("key: " + key)

    ciphertext_alpha_list = []
    for pos, char in enumerate(plaintext_alpha):
        ciphertext_alpha_list.append(chr(((ord(char) + ord(key[pos])) % 26) + 65))
    ciphertext_alpha = ''.join(ciphertext_alpha_list)

    ciphertext = reapplystructure(ciphertext_alpha, plaintext)
    print("ciphertext: " + ciphertext)

def decrypt(args):
    print("decrypt")
    ciphertext = args.ciphertext.upper()
    print("ciphertext: " + ciphertext)
    ciphertext_alpha = alphaonly(ciphertext)
    key = alphaonly(args.key.upper())
    if len(key) < len(ciphertext_alpha):
        raise Exception("""The number of alphabetic characters in the key must
                        be longer than the number alphabetic charaters in the plaintext""")
    print("Key: " + key)

    plaintext_alpha_list = []
    for pos, char in enumerate(ciphertext_alpha):
        plaintext_alpha_list.append(chr(((ord(char) - ord(key[pos])) % 26) + 65))
    plaintext_alpha = ''.join(plaintext_alpha_list)

    plaintext = reapplystructure(plaintext_alpha, ciphertext)
    print(plaintext)

def alphaonly(text):
    return ''.join(re.findall("[A-Z]+", text))

def reapplystructure(alpha, structure):
    alpha_list = list(alpha)
    for pos, char in enumerate(structure):
        if not char.isalpha():
            alpha_list.insert(pos, char)
    text = ''.join(alpha_list)
    return text


if __name__ == "__main__":
    main()
