#include "c01.hxx"
#include "c07.hxx"
#include "c03.hxx"


void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

/* This code is extract from forum: https://stackoverflow.com/questions/38342326/aes-256-encryption-with-openssl-library-using-ecb-mode-of-operation */
void encrypt_aes_128_in_ecb(const uint8_t* plaintextArray, const int lenPlaintextArray, const bool pad, const uint8_t* keyArray, int& lenCiphertextArray, uint8_t* &ciphertextArray)
{
/** @brief  Algorithm which computes the AES-128 encryption of an array plaintext in the mode ECB
 *  @param  plaintextArray       The byte array which contains plaintext
 *  @param  lenPlaintextArray    The length of the input plaintext byte array
 *  @param  keyArray          The array which contains secret key
 *  @param  lenCiphertextArray    The length of the output ciphertext array
 *  @param  ciphertextArray       The array which contains ciphertext
 */
    EVP_CIPHER_CTX *ctx;    
    int len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * In this example we are using 256 bit AES (i.e. a 256 bit key). 
    */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, keyArray, NULL))  handleErrors();

    /* enable or desable the padding at the end of plaintext 
       for this case, length of plaintext should be a multiple of block
    */
    EVP_CIPHER_CTX_set_padding(ctx, pad);

    /*initialize ciphertext array with the length of plaintext plus the size of one block = 16 bytes*/
    ciphertextArray = new uint8_t[lenPlaintextArray + 16];

    /* Provide the message to be encrypted, and obtain the encrypted output.
    * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if(1 != EVP_EncryptUpdate(ctx, ciphertextArray, &len, plaintextArray, lenPlaintextArray))
        handleErrors();
    lenCiphertextArray = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
    * this stage.
    */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertextArray + len, &len))  handleErrors();
    lenCiphertextArray += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void decrypt_aes_128_in_ecb(const uint8_t* ctxtArray, const int lenCtxtArray, const bool pad, const uint8_t* aesKeyArray, int& lenPtxtArray, uint8_t* &ptxtArray)
{
/** @brief  Algorithm which computes the AES-128 decryption of an array ciphertext in the mode ECB
 *  @param  ctxtArray       The array which contains ciphertext
 *  @param  lenCtxtArray    The length of the input ciphertext byte array
 *  @param  aesKey          The array which contains secret key
 *  @param  lenPtxtArray    The length of the output plaintext array
 *  @param  ptxtArray       The array which contains plaintext
 */
    EVP_CIPHER_CTX *ctx;

    int len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
    * In this example we are using 128 bit AES (i.e. a 128 bit key). The
    */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, aesKeyArray, NULL)) handleErrors();
    
    /* enable or desable the padding at the end of plaintext 
       for this case, length of plaintext should be a multiple of block
    */
    EVP_CIPHER_CTX_set_padding(ctx, pad);

    ptxtArray = new uint8_t[lenCtxtArray];

    /* Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_DecryptUpdate can be called multiple times if necessary
    */

    if(1 != EVP_DecryptUpdate(ctx, ptxtArray, &len, ctxtArray, lenCtxtArray)) handleErrors();
    lenPtxtArray = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
    * this stage.
    */
    if(1 != EVP_DecryptFinal_ex(ctx, ptxtArray + len, &len)) handleErrors();
    lenPtxtArray += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void decryption_aes_128_in_ecb_mode(const std::string inputFileName, const std::string aesKeyStr, std::string& outputFileName)
{
/** @brief  Algorithme which computes AES-128 decryption in ECB mode for a text contains in a file
 *  @param  inputFileName   The string which contains fullname where to find file
 *  @param  aesKeyStr       The string which contains secret key use to decrypt text
 *  @param  outputFileName  The string which contains fullname where file will be saved
 */
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

        /*for this challenge, we use autopadding of decryption*/
        bool pad = 1;

        uint8_t* ctxtArray;
        int lenCtxtArray;

        /* Encode string ciphertext into an array of bytes */
        string_to_bytes(ctxtStr, lenCtxtArray, ctxtArray);

        uint8_t* aesKeyArray;
        int lenAesKeyArray;
        string_to_bytes(aesKeyStr, lenAesKeyArray, aesKeyArray);

        uint8_t* ptxtArray;
        int lenPtxtArray;
        decrypt_aes_128_in_ecb(ctxtArray, lenCtxtArray, pad, aesKeyArray, lenPtxtArray, ptxtArray);

        std::string ptxtStr;
        bytes_to_string(ptxtArray, lenPtxtArray, ptxtStr);

        std::cout << "\nDecrypted text is : \n" << std::endl;
        std::cout << ptxtStr << std::endl;

        std::ofstream myOutStream(outputFileName.c_str());
        if (myOutStream)
        {
            myOutStream << ptxtStr;
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
