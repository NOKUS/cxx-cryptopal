#include "c01.hxx"
#include "c07.hxx"
#include "test_c07.hxx"

bool test_aes_128_ecb()
{
    std::string keyStr = "YELLOW SUBMARINE";
    std::string challenge0Str = "";//empty plaintext;
    std::string challenge1Str = "Hello Word!";//plaintext with less than 16 bytes
    std::string challenge2Str = "Hello Word!!!!!!"; //plaintext with exactly 16 bytes
    std::string challenge3Str = "Hello Word! I'm a test for AES symmetric encryption for block of 16 bytes in the ECB mode";

    uint8_t* keyArray;
    int lenKeyArray;
    string_to_bytes(keyStr, lenKeyArray, keyArray);

    uint8_t* challenge0Array;
    int lenChallenge0Array;
    string_to_bytes(challenge0Str, lenChallenge0Array, challenge0Array);

    uint8_t* challenge1Array;
    int lenChallenge1Array;
    string_to_bytes(challenge1Str, lenChallenge1Array, challenge1Array);

    uint8_t* challenge2Array;
    int lenChallenge2Array;
    string_to_bytes(challenge2Str, lenChallenge2Array, challenge2Array);

    uint8_t* challenge3Array;
    int lenChallenge3Array;
    string_to_bytes(challenge3Str, lenChallenge3Array, challenge3Array);

    uint8_t* ciphertext0Array;
    int lenCiphertext0Array;

    uint8_t* ciphertext1Array;
    int lenCiphertext1Array;

    uint8_t* ciphertext2Array;
    int lenCiphertext2Array;

    uint8_t* ciphertext3Array;
    int lenCiphertext3Array;

    uint8_t* plaintext0Array;
    int lenPlaintext0Array;

    uint8_t* plaintext1Array;
    int lenPlaintext1Array;

    uint8_t* plaintext2Array;
    int lenPlaintext2Array;

    uint8_t* plaintext3Array;
    int lenPlaintext3Array;

    bool pad = 1;


    encrypt_aes_128_in_ecb(challenge0Array, lenChallenge0Array, pad, keyArray, lenCiphertext0Array, ciphertext0Array);
    encrypt_aes_128_in_ecb(challenge1Array, lenChallenge1Array, pad, keyArray, lenCiphertext1Array, ciphertext1Array);
    encrypt_aes_128_in_ecb(challenge2Array, lenChallenge2Array, pad, keyArray, lenCiphertext2Array, ciphertext2Array);
    encrypt_aes_128_in_ecb(challenge3Array, lenChallenge3Array, pad, keyArray, lenCiphertext3Array, ciphertext3Array);

    decrypt_aes_128_in_ecb(ciphertext0Array, lenCiphertext0Array, pad, keyArray, lenPlaintext0Array, plaintext0Array);
    decrypt_aes_128_in_ecb(ciphertext1Array, lenCiphertext1Array, pad, keyArray, lenPlaintext1Array, plaintext1Array);
    decrypt_aes_128_in_ecb(ciphertext2Array, lenCiphertext2Array, pad, keyArray, lenPlaintext2Array, plaintext2Array);
    decrypt_aes_128_in_ecb(ciphertext3Array, lenCiphertext3Array, pad, keyArray, lenPlaintext3Array, plaintext3Array);

    std::string plaintext0Str;
    std::string plaintext1Str;
    std::string plaintext2Str;
    std::string plaintext3Str;

    bytes_to_string(plaintext0Array, lenPlaintext0Array, plaintext0Str);
    bytes_to_string(plaintext1Array, lenPlaintext1Array, plaintext1Str);
    bytes_to_string(plaintext2Array, lenPlaintext2Array, plaintext2Str);
    bytes_to_string(plaintext3Array, lenPlaintext3Array, plaintext3Str);

    /*
    std::cout << "plaintext0 = " << plaintext0Str << std::endl;
    std::cout << "plaintext1 = " << plaintext1Str << std::endl;
    std::cout << "plaintext2 = " << plaintext2Str << std::endl;
    std::cout << "plaintext3 = " << plaintext3Str << std::endl;
    */
    return (plaintext0Str == challenge0Str) && (plaintext1Str == challenge1Str) && (plaintext2Str == challenge2Str) && (plaintext3Str == challenge3Str);
}
