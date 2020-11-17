#include "c01.hxx"
#include "c07.hxx"
#include "c08.hxx"
#include "c09.hxx"
#include "c11.hxx"
#include "c12.hxx"

void encryption_ecb_oracle(const uint8_t* plaintextArray, const int lenPlaintextArray, int& lenCiphertextArray, uint8_t*& ciphertextArray)
{
/** @brief  A oracle which take a plaintext, pads a unknow text and encypts all of them with AES in ECB mode, with an unknow key. 
 *  @param  plaintextArray      Text which should be encrypted by oracle
 *  @param  lenPlaintextArray   length of array which containt plaintext
 *  @param  lenCiphertextArray  length of array which containt ciphertext produice by oracle
 *  @param  ciphertextArray     Text which is output of encryption on plaintextArray by the oracle
 */

    /* Consistent Key for Oracle encryption */
    std::string consistentKeyStr = "0123456789abcdf";
    uint8_t* consistentKeyArray;
    int lenConsistentKeyArray;
    string_to_bytes(consistentKeyStr, lenConsistentKeyArray, consistentKeyArray);

    /* Convert text to pad into byte array */
    std::string textBeforeEncryptingStr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    uint8_t* textBeforeEncryptingArray;
    int lenTextBeforeEncryptingArray;
    base64_to_hex_array(textBeforeEncryptingStr, lenTextBeforeEncryptingArray, textBeforeEncryptingArray);

    /* pad plaintext with text before encrypting */
    int lenPaddedPlaintextArray = lenPlaintextArray + lenTextBeforeEncryptingArray;
    uint8_t* paddedPlaintextArray = new uint8_t[lenPaddedPlaintextArray];
    std::copy(plaintextArray, plaintextArray + lenPlaintextArray, paddedPlaintextArray);
    std::copy(textBeforeEncryptingArray, textBeforeEncryptingArray + lenTextBeforeEncryptingArray, paddedPlaintextArray + lenPlaintextArray);

    
    /* Encrypt padded text with AES 128 in ECB mode with consistent key */
    encrypt_aes_128_in_ecb(paddedPlaintextArray, lenPaddedPlaintextArray, 1, consistentKeyArray, lenCiphertextArray, ciphertextArray);
}

void block_size_cipher(int& blockLen)
{
/** @brief  Find the block size of AES used by oracle
 *  @param  blockLen    The length of block AES used by oracle
 */
    bool blocksAreEquals = 0;

    blockLen = 1;
    while (!blocksAreEquals)
    {
        blockLen++;
        int lenPlaintextArray = blockLen;
        uint8_t plaintextArray[lenPlaintextArray] = {0};

        uint8_t* ciphertextArray;
        int lenCiphertextArray;
        encryption_ecb_oracle(plaintextArray, lenPlaintextArray, lenCiphertextArray, ciphertextArray);

        blocksAreEquals = 1;
        for (int i = 0; i < blockLen/2; i++)
        {
            blocksAreEquals &= (ciphertextArray[i] == ciphertextArray[blockLen/2 + i]);
        }
    }    

    blockLen /=2;
}

void detect_aes_mode(bool& isEcbMode)
{
/** @brief Check if oracle is using AES in ECB mode or No
 *  @param  isEcbMode   the answer algorithm
 */
    std::string plaintextStr = "";
    for (int i = 0; i < 1024; i++)
    {
        plaintextStr += "A";
    }
    uint8_t* plaintextArray;
    int lenPlaintextArray;
    string_to_bytes(plaintextStr, lenPlaintextArray, plaintextArray);

    uint8_t* ciphertextArray;
    int lenCiphertextArray;
    encryption_ecb_oracle(plaintextArray, lenPlaintextArray, lenCiphertextArray, ciphertextArray);

    std::string detectedMode;
    detect_block_cipher_mode(ciphertextArray, lenCiphertextArray, detectedMode);
    isEcbMode = (detectedMode == "ECB");
}

void ecb_decryption(int& lenPlaintextArray, uint8_t*& plaintextArray)
{
/** @brief  Algorithm which decrypt the unknow text used by oracle when it encrypts some plaintext
 *  @param  lenPlaintextArray   The length of the array which contains unknow text used by oracle
 *  @param  plaintextArray      array which contains unknow text used by oracle.
 */
    bool isEcbMode;
    detect_aes_mode(isEcbMode);

    if (!isEcbMode)
    {
        std::cerr << "The used Oracle do not use ECB mode when it encrypts text." << std::endl;
    }
    else
    {
        /* Get length of block in the oracle encryption */
        int blockLen;
        block_size_cipher(blockLen);

        /* Get the length of plaintext with padding used by oracle */
        uint8_t* tmpArray = new uint8_t[0];
        int lenPaddedPlaintextArray;
        encryption_ecb_oracle(tmpArray, 0, lenPaddedPlaintextArray, tmpArray);
        uint8_t* paddedPlaintextArray = new uint8_t[lenPaddedPlaintextArray];

        int blockCpter = 0;
        int padCpter = blockLen - 1;

        /*  Initialize an array of length equal to padded plaintext array and with common value, here '0'
            for block length = 4 and number of block = 5, we have 
            refPlaintextArray =                 |0|0|0|0| |0|0|0|0| |0|0|0|0| |0|0|0|0| |0|0|0|0|
        */
        
        uint8_t refPlaintextArray[lenPaddedPlaintextArray] = {0};

        for (int i = 0; i < lenPaddedPlaintextArray; i++)
        {
            uint8_t* refCiphertextArray;
            int lenRefCiphertextArray;
            /*  Contains the length of '0'-padding in the reference plaintext  */
            int lenRefPlaintextArray = lenPaddedPlaintextArray - (blockCpter + blockLen) + padCpter;
            /*  At a stage where blockCpter = 2 and padCpter = 3, reference plaintext inter in algorithm with value
                refPlaintextArray =             |0|0|0|0| |0|0|0|0| |0|0|0|
                and reference ciphertext associed lock like
                refCiphertextArray =    AES_ECB(|0|0|0|0| |0|0|0|0| |0|0|0|x| |x|x|x|x| |x|x|x|?| |?|?|?|?| |?|?|?|?| ... ) 
                where   'x' = already decrypted value
                        '?' = unknow value
                        '0' = input padding value

            */
            encryption_ecb_oracle(refPlaintextArray, lenRefPlaintextArray, lenRefCiphertextArray, refCiphertextArray);



            int lenDetectorPlaintextArray = blockCpter + blockLen;
            /*  To define detector plaintext, we pad the array in inverse order of reference plaintext
                At the stage where blockCpter = 2 and padCpter = 3 detector plaintext start with:
                detectorPlaintext = |0|0|0|0| |0|0|0|0| |0|0|0|0|
            */
            uint8_t detectorPlaintextArray[lenDetectorPlaintextArray] = {0};
            
            int ind = 0;
            /*  Here we fit detectorPlaintext with plaintext value already know except the last byte of the last block
                detectorPlaintext = |0|0|0|x| |x|x|x|x| |x|x|x|0| 
            */
            for (int j = padCpter; j < lenDetectorPlaintextArray - 1; j++)
            {
                detectorPlaintextArray[j] = paddedPlaintextArray[ind];
                ind++;
            }

            /*  Here we find the byte which replace the last byte of detectorPlaintext            
            */
            
            for (int byte = 0; byte < 256; byte++)
            {
                /* detectorPlaintext = |0|0|0|x| |x|x|x|x| |x|x|x|byte| */
                detectorPlaintextArray[lenDetectorPlaintextArray - 1] = byte;

                int lenDetectorCiphertextArray;
                uint8_t* detectorCiphertextArray;

                /*  We use oracle to encrypt these blocks of detectorPlaintext 
                    The output locks like
                    detectorCiphertext = AES_ECB(|0|0|0|x| |x|x|x|x| |x|x|x|byte| |?|?|?|?| |?|?|?|?| ...)
                    Here block with '?' don't interest us
                */
                encryption_ecb_oracle(detectorPlaintextArray, lenDetectorPlaintextArray, lenDetectorCiphertextArray, detectorCiphertextArray);

                /*  Here as Oracle use AES in ECB mode, we have
                    refCiphertextArray  =   AES_ECB(|0|0|0|0| |0|0|0|0| |0|0|0|x| |x|x|x|x| |x|x|x|?| |?|?|?|?| |?|?|?|?| ... )
                                        =   AES(|0|0|0|0|) || AES(|0|0|0|0|) || AES(|0|0|0|x|) || AES(|x|x|x|x|) || AES(|x|x|x|?|) || AES(|?|?|?|?|) || AES(|?|?|?|?|) ... 
                    and

                    detectorCiphertext  =   AES_ECB(|0|0|0|x| |x|x|x|x| |x|x|x|byte| |?|?|?|?| |?|?|?|?| ...)
                                        =   AES(|0|0|0|x|) || AES(|x|x|x|x|) || AES(|x|x|x|byte|) || AES(|?|?|?|?|) || AES(|?|?|?|?|) ...
                    
                    so, we only have to check if "lenDetectorPlaintextArray" bit which begin detectorCiphertext are the same as those beginning at position 
                    "lenPaddedPlaintextArray - (blockCpter + blockLen)" in the refCiphertext
                */
                bool isBlockEqual = 1;
                for (int u = 0; u < lenDetectorPlaintextArray; u++)
                {
                    isBlockEqual &= (detectorCiphertextArray[u] == refCiphertextArray[lenPaddedPlaintextArray - (blockCpter + blockLen) + u]);
                }                

                /*  If for a value of 'byte', previous block are equal, this means we have find byte at position "i" in the plaintext
                */
                if (isBlockEqual)
                {
                    paddedPlaintextArray[i] = byte;
                    padCpter--;
                    if(padCpter == -1)
                    {
                        padCpter = blockLen -1;
                        blockCpter += blockLen;
                    }
                    break;
                }
                
            }            
            
        }
        
        pkcs7_unpadding_bytes(paddedPlaintextArray, lenPaddedPlaintextArray, lenPlaintextArray, plaintextArray);        
    }    
}