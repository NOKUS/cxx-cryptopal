#include "c02.hxx"
#include "c07.hxx"
#include "c09.hxx"
#include "c10.hxx"
#include <algorithm>

void encrypt_aes_in_cbc(const int lenBlock, const uint8_t* plaintextArray, const int lenPlaintextArray, const bool pad, const uint8_t* key, const uint8_t* IV, int& lenCiphertextArray, uint8_t*& ciphertextArray)
{
/** @brief  Algorithm which computes the AES encryption of an array plaintext in CBC mode
 *  @param  lenBlock                The length of the blocks
 *  @param  plaintextArray          The byte array which contains plaintext
 *  @param  lenPlaintextArray       The length of the input plaintext byte array
 *  @param  pad                     The bit which define if algorithm should use autopadding or not
 *  @param  key                     The array which contains secret key
 *  @param  IV                      The initialization vector 
 *  @param  lenCiphertextArray      The length of the output ciphertext array
 *  @param  ciphertextArray         The array which contains ciphertext
 */
    uint8_t* paddedPlaintext;
    int lenPaddedPlaintext;
    /* Pad plaintext until its length become a multiple of block size */
    pkcs7_padding_bytes(lenBlock, plaintextArray, lenPlaintextArray, lenPaddedPlaintext, paddedPlaintext);

    /* initialize the ciphertext length to the length of padded plaintext */
    lenCiphertextArray = lenPaddedPlaintext;
    ciphertextArray = new uint8_t[lenCiphertextArray];

    /* Define the previous ciphertext block which is initialize with initilisation vector IV */
    uint8_t* previousCiphertext = new uint8_t[lenBlock];
    std::copy(IV, IV + lenBlock, previousCiphertext);

    /*Define currect block to encrypt with AES in CBC mode */
    uint8_t* currentCiphertext = new uint8_t[lenBlock];
    int lenCurrentCtxt;

    /* Get the number of block in the padded plaintext */
    int nbrBlock = lenPaddedPlaintext/lenBlock;
    for (int i = 0; i < nbrBlock; i++)
    {
        /* get the currect block which should be encrypted */
        std::copy(paddedPlaintext + lenBlock*i, paddedPlaintext + lenBlock*(i + 1), currentCiphertext);

        /* xor with the previous encrypted block and save the result in currentCiphertext */
        bytes_array_fixed_xor(currentCiphertext, lenBlock, previousCiphertext, lenBlock, lenCurrentCtxt, currentCiphertext);

        /* Encrypt the current block with AES 128 in ECB mode and save the result in the currentCiphertext */
        encrypt_aes_128_in_ecb(currentCiphertext, lenCurrentCtxt, pad, key, lenCurrentCtxt, currentCiphertext);

        /* Save the encrypted block in the array of output ciphertext */
        std::copy(currentCiphertext, currentCiphertext + lenBlock, ciphertextArray + lenBlock*i);
        
        /* Update the previous ciphertext block with the current ciphertext block */
        std::copy(currentCiphertext, currentCiphertext + lenBlock, previousCiphertext);
    }
}

void decrypt_aes_in_cbc(const int lenBlock, const uint8_t* ciphertextArray, const int lenCiphertextArray, const bool pad, const uint8_t* key, uint8_t* IV, int& lenPlaintextArray, uint8_t*& plaintextArray)
{
/** @brief  Algorithm which computes the AES-128 decryption of an array ciphertext in the CBC mode
 *  @param  lenBlock                The length of the blocks
 *  @param  ciphertextArray         The array which contains ciphertext
 *  @param  lenCiphertextArray      The length of the input ciphertext byte array
 *  @param  pad                     The bit which define if algorithm should use autopadding or not
 *  @param  key                     The array which contains secret key
 *  @param  IV                      The initialization vector 
 *  @param  lenPlaintextArray       The length of the output plaintext array
 *  @param  plaintextArray          The array which contains plaintext
 */

    /* currect block to decrypt with AES in CBC mode */
    uint8_t* currentCiphertext = new uint8_t[lenBlock];
    int lenCurrentCtxt = lenBlock;

    /* next ciphertext block to decrypt, the last one is associed to IV */
    uint8_t* nextCiphertext = new uint8_t[lenBlock];
    int lenNextCtxt = lenBlock; 

    /*array which contains plaintext with padding*/
    int lenPaddedPlaintext = lenCiphertextArray;
    uint8_t* paddedPlaintext = new uint8_t[lenPaddedPlaintext];

    int nbrBlock = lenCiphertextArray/lenBlock;
    for (int i = (nbrBlock - 1); i > 0 ; i--)
    {
        /* get the currect block which should be decrypted */
        std::copy(ciphertextArray + lenBlock*i, ciphertextArray + lenBlock*(i+1), currentCiphertext);
        
        /* get the next block which should be decrypted and which is use to decrypt current block */
        std::copy(ciphertextArray + lenBlock*(i-1), ciphertextArray + lenBlock*i, nextCiphertext);

        /* decrypt current block with aes in ecb mode */
        decrypt_aes_128_in_ecb(currentCiphertext, lenCurrentCtxt, pad, key, lenCurrentCtxt, currentCiphertext);

        /* xor the current block with the next block */
        bytes_array_fixed_xor(currentCiphertext, lenCurrentCtxt, nextCiphertext, lenNextCtxt, lenCurrentCtxt, currentCiphertext);

        /* append current block in the padding plaintext array */
        std::copy(currentCiphertext, currentCiphertext + lenCurrentCtxt, paddedPlaintext + lenBlock*i);
    }

    /* Threat the last block */

    /* decrypt the first block with AES ECB*/
    decrypt_aes_128_in_ecb(ciphertextArray, lenBlock, pad, key, lenCurrentCtxt, currentCiphertext);

    /* xor the first block decrypted with IV */
    bytes_array_fixed_xor(currentCiphertext, lenCurrentCtxt, IV, lenBlock, lenCurrentCtxt, currentCiphertext);

    /* append first block to padded plaintext array */
    std::copy(currentCiphertext, currentCiphertext + lenCurrentCtxt, paddedPlaintext);        

    /* remove padding added before encryption */
    pkcs7_unpadding_bytes(paddedPlaintext, lenPaddedPlaintext, lenPlaintextArray, plaintextArray);
}

void decrypt_cbc_text(const std::string inputFileName, const std::string keyStr, const std::string IVStr, std::string& outputFileName)
{
/** @brief  Algorithme which computes AES decryption in CBC mode for a text contains in a file
 *  @param  inputFileName   The string which contains fullname where to find file
 *  @param  keyStr          The string which contains secret key use to decrypt text
 *  @param  IVStr           The initialization vector
 *  @param  outputFileName  The string which contains fullname where file will be saved
 */
    int lenBlock = 16;
    std::ifstream myInStream(inputFileName.c_str());    
    if (myInStream)
    {
        std::string ctxtStr = "";
        base64 base64LineStr;
        std::string ctxtLineStr;

        while (getline(myInStream, base64LineStr))
        {
            /* In this case, the decoded text is a hexa string */
            base64_to_string(base64LineStr, ctxtLineStr);
            ctxtStr += ctxtLineStr;
        }

        /*For this challenge, we do not use autopadding in encryption/decryption with AES-ECB */
        bool pad = 0;

        uint8_t* ciphertextArray;
        int lenCiphertextArray;

        /* Encode string ciphertext into an array of bytes */
        string_to_bytes(ctxtStr, lenCiphertextArray, ciphertextArray);

        uint8_t* keyArray;
        int lenKeyArray;
        string_to_bytes(keyStr, lenKeyArray, keyArray);

        uint8_t* IVArray;
        int lenIVArray;
        hex_string_to_hex_array(IVStr, lenIVArray, IVArray);
        //string_to_bytes(IVStr, lenIVArray, IVArray);

        uint8_t* plaintextArray;
        int lenPlaintextArray;
        decrypt_aes_in_cbc(lenBlock, ciphertextArray, lenCiphertextArray, pad, keyArray, IVArray, lenPlaintextArray, plaintextArray);

        std::string plaintextStr;
        bytes_to_string(plaintextArray, lenPlaintextArray, plaintextStr);

        std::cout << "\nDecrypted text is : \n" << std::endl;
        std::cout << plaintextStr << std::endl;

        std::ofstream myOutStream(outputFileName.c_str());
        if (myOutStream)
        {
            myOutStream << plaintextStr;
        }
        else
        {
            std::cerr << "Error! file:" << outputFileName << "couldn't open." << std::endl;
        }
    
    }
    else
    {
        std::cerr << "Error! file:" << inputFileName << "couldn't open." << std::endl;
    }
}