from aes import AES


def main():
    # change this to see encryption and decryption at
    # different key sizes
    keysize = 256

    # Federal InformationProcessing Standards Publication 197,
    # Appendix c test cases for 3 key sizes
    plaintext = 0x00112233445566778899aabbccddeeff

    key128 = 0x000102030405060708090a0b0c0d0e0f
    key192 = 0x000102030405060708090a0b0c0d0e0f1011121314151617
    key256 = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

    aes = AES(True)

    if keysize == 128:
        kMatrix = aes.toMatrix(key128, 16)
    elif keysize == 192:
        kMatrix = aes.toMatrix(key192, 24)
    elif keysize == 256:
        kMatrix = aes.toMatrix(key256, 32)
    else:
        exit('Invalid keysize given')

    pMatrix = aes.toMatrix(plaintext)

    print('Encryption with ' + str(keysize) + ' bit key')
    e = aes.cipher(pMatrix, kMatrix, keysize)
    print('Decryption with ' + str(keysize) + ' bit key')
    decrypted = aes.invCipher(e, kMatrix, keysize)

if __name__ == "__main__":
    main()