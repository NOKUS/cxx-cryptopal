#include "lib.hxx"
#include "c02.hxx"
#include "c03.hxx"
#include "c06.hxx"


void hamming_weight(const uint8_t* input, const int lenInput, int& output)
{
/** @brief  compute the Hamming weight of an integer represented as bytes array
 *  @param  input       bytes array of a integer that we want to compute hamming weight
 *  @param  lenInput    length of the input bytes array
 *  @param  output      the hamming weight of input.
 */

    output = 0;
    for (int i = 0; i < lenInput; i++)
        for (int j = 0; j < 8; j++)
            output += (input[i] >> j) & 0b00000001;
    
}

void hamming_distance(const uint8_t* input0, const int lenInput0, const uint8_t* input1, const int lenInput1, int& output)
{
/** @brief  Compute Hamming distance between two integers represented as bytes array of same length
 *  @param  input0      bytes array which represents the first integer
 *  @param  lenInput0   length of firt input bytes array
 *  @param  input1      bytes arrays which represents the second integer
 *  @param  lenInput1   length of secont input bytes array
 *  @param  output      the hamming distance between input0 and input1
 */

    uint8_t* tmpOutput;
    int tmpLenOutput;
    bytes_array_fixed_xor(input0, lenInput0, input1, lenInput1, tmpLenOutput, tmpOutput);
    hamming_weight(tmpOutput, tmpLenOutput, output);
}

void find_key_size(const uint8_t* input, const int lenInput, int& KEYSIZE)
{
/** @brief  Find the key size for a ciphertext encrypted with Vigenere encryption.
 *  @param  input       A bytes array which represents a ciphertext.
 *  @param  lenInput    Length of input array.
 *  @param  KEYSIZE     The size of key which encrypts the input ciphertext.
 */

    float minimalScore = +INFINITY;

    for (int probableKeySize = 2; probableKeySize <= 40; probableKeySize++)
    {
        float score = 0;
        for(int i = 0; i < (lenInput - 2*probableKeySize); i++)
        {
            int tmpScore = 0;
            hamming_distance(&input[i], probableKeySize, &input[i + probableKeySize], probableKeySize, tmpScore);
            score += tmpScore;
        }

        score /= probableKeySize;

        if (score < minimalScore)
        {
            minimalScore = score;
            KEYSIZE = probableKeySize;
        }        
    }
}

void partition_text(const uint8_t* input, const int lenInput, const int KEYSIZE, int &communLenOutput, uint8_t** &arrayOfOutput)
{
/** @brief  Partition the input text into a set of KEYSIZE text where arrayOfOutput[i] is the text composed of all character at position i%KEYSIZE in the input text
 *  @param  input           bytes array which correspond to text to partition into a set of KEYSIZE text
 *  @param  lenInput        the length of input bytes array text
 *  @param  KEYSIZE         the length of key which encrypts input text with Vigenere Algorithm
 *  @param  commonLenOutput common length of each bytes array in the set of text
 *  @param  arrayOfOutput   set (array of pointer to bytes array) of (bytes array) text partitioned from input (bytes array) text
 */

    arrayOfOutput = new uint8_t*[KEYSIZE];
    communLenOutput = lenInput/KEYSIZE;
    int rest = lenInput - (communLenOutput * KEYSIZE);

    communLenOutput++;
    std::cout << "communLenOutput = " << communLenOutput << " lenInput = " << lenInput <<std::endl;
    for (int i = 0; i < KEYSIZE; i++)
        arrayOfOutput[i] = new uint8_t[communLenOutput];

    for (int i = 0; i < KEYSIZE; i++)
        for (int j = 0; j <  (communLenOutput - 1); j++)
        {
            arrayOfOutput[i][j] = input[i + KEYSIZE*j];
        }

    if (rest != 0)
        for (int i = 0; i < rest; i++)
            arrayOfOutput[i][communLenOutput-1] = input[KEYSIZE*(communLenOutput - 1) + i];

/*
    std::cout << "inputStr = " << std::endl;
    for (int i = 0; i < lenInput; i++)
    {
        if ((i % (KEYSIZE)) == 0)
        {
            std::cout << "\n";
            std::cout << (int)input[i] << " ";
        }
        else
            std::cout << (int)input[i] << " ";
    }
    std::cout<< "\n----\n" <<std::endl;

    for (int i = 0; i < KEYSIZE; i++)
    {
        std::cout << "set[" << i << "] = " << std::endl;
        for (int j = 0; j < communLenOutput; j++)
        {
            std::cout <<(int) arrayOfOutput[i][j] << " ";
        }
        std::cout << "\n" << std::endl;
        
    }
*/ 
    
}

void find_key(uint8_t** setInputArray, const int communLenInput, const int KEYSIZE, uint8_t* &KEY)
{
/** @brief  From partitionned Vigenere ciphertext and KEYSIZE, extract de secret key
 *  @param  setInputArray      a set (array of pointer to bytes array) of text partitioned
 *  @param  communLenInput  a commun length of each array in the set of input array
 *  @param  KEYSIZE         the size of Vigenere key which encrypts set of input array
 *  @param  KEY             the key of Vigenere which encrypts set of input array
 */
    float bestScore;
    int lenOutputArray;
    uint8_t* outputArray;
    KEY = new uint8_t[KEYSIZE];

    for (int i = 0; i < KEYSIZE; i++)
    {
        single_byte_xor_cipher(setInputArray[i], communLenInput, bestScore, KEY[i], lenOutputArray, outputArray);
        std::cout << "KEY[" << i << "] = " << (int)KEY[i] << std::endl;
    }
}

void decrypt_vigenere(const uint8_t* ctxtArray, const int lenCtxtArray, const int KEYSIZE, const uint8_t* encryptedKeyArray, int &lenPtxtArray, uint8_t* &ptxtArray)
{
/** @brief  Decrypt ciphertext array encrypted with the Vigenere algorithm
 *  @param  ctxtArray           Ciphertext array which is encrypted by Vigenere algorithm
 *  @param  lenCtxtArray        Length of input ciphertext array
 *  @param  KEYSIZE             Size of the key which encrypts the ciphertext array.
 *  @param  encryptedKeyArray   Array which contains encryption key
 *  @param  lenPtxtArray        Length of array which contains decrypted text
 *  @param  ptxtArray           Array which contains decrypted text.
 */

    lenPtxtArray = lenCtxtArray;
    ptxtArray = new uint8_t[lenPtxtArray];

    for (int i = 0; i < lenPtxtArray; i++)
    {
        ptxtArray[i] = ctxtArray[i] ^ encryptedKeyArray[i%KEYSIZE];
    }
    
}

void break_repeating_key_xor(const std::string inputFileName, std::string &KEY, std::string &outputFileName)
{
/** @brief  Take a file name which contains text encrypted by a Vigenere algorithm and return a file which contains decrypted text and decryption key.
 *  @param  inputFileName   File which contains encrypted text
 *  @param  KEY             Key which is used to encrypt text in the input file
 *  @param  outputFileName  File which contains decrypted text
 */

    std::ifstream myInStream(inputFileName.c_str());
    
    if (myInStream)
    {
        std::string ctxtStr = "";
        base64 base64LineStr;
        std::string lineStr;
        std::string base64CtxtStr = "";
        std::string ctxtLineStr;

        while (getline(myInStream, base64LineStr))
        {
            base64_to_string(base64LineStr, ctxtLineStr);
            ctxtStr += ctxtLineStr;
            std::cout << "ctxtStr     : " << ctxtStr << "\n" << std::endl;
            std::cout << "ctxtLineStr : " << ctxtLineStr << "\n\n" << std::endl;
        }

        
        //base64_to_string(base64CtxtStr, ctxtStr);
        //std::cout << "lineStr : " << lineStr << std::endl;
        //ctxtStr += lineStr;
        //std::cout << "ctxtStr : " << ctxtStr << std::endl;
        

        //std::cout << "encrypted ctxt : \n" << ctxtStr << std::endl;
        uint8_t* ctxtArray;
        int lenCtxtArray;

        string_to_bytes(ctxtStr, lenCtxtArray, ctxtArray);
        //base64_to_hex_array(base64CtxtStr, lenCtxtArray, ctxtArray);

        int KEYSIZE = 0;
        find_key_size(ctxtArray, lenCtxtArray, KEYSIZE);

        int communLenCtxtArray;
        uint8_t** setOfCtxtArray;
        partition_text(ctxtArray, lenCtxtArray, KEYSIZE, communLenCtxtArray, setOfCtxtArray);

        uint8_t* encryptionKeyArray;
        find_key(setOfCtxtArray, communLenCtxtArray, KEYSIZE, encryptionKeyArray);
        std::cout << "encryptionKeyArray[0] = " << (int)encryptionKeyArray[1] << std::endl;

        int lenPtxtArray;
        uint8_t* ptxtArray;
        decrypt_vigenere(ctxtArray, lenCtxtArray, KEYSIZE, encryptionKeyArray, lenPtxtArray, ptxtArray);

        std::string ptxtStr;
        bytes_to_string(ptxtArray, lenPtxtArray, ptxtStr);
        bytes_to_string(encryptionKeyArray, KEYSIZE, KEY);

        std::ofstream myOutStream(outputFileName.c_str());
        if (myOutStream)
        {
            myOutStream << ptxtStr;
        }
        else
        {
            std::cerr << "Error! file:" << inputFileName << "couldn't open." << std::endl;
        }
    }
    else
    {
        std::cerr << "Error! file:" << inputFileName << "couldn't open." << std::endl;
    }
}