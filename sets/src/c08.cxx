#include "c08.hxx"


void nbr_of_different_block(const std::string ctxtHexStr, int& nbrOfBlocks)
{
/** @brief  Compute the number of different 16 bytes blocks in the input ciphertext string
 *  @param  ctxtHexStr      A hex string which represents a ciphertext from one cryptographic algorithm
 *  @param  nbrOfBlocks     The number of different 16 bytes blocks in ctxtHexStr
 */
    std::map <std::string, int> blockOccurrence;
    /* 
    As input is a hex-encoded string, 1 byte is represented by 2 chars 
    then 16 bytes are represented by 32 chars in the string
     */
    int n = ctxtHexStr.length()/32;
    for (int i = 0; i < n; i++)
    {
        ++blockOccurrence[ctxtHexStr.substr(32*i, 32)];
    }
    
    nbrOfBlocks = blockOccurrence.size();
}

void detect_aes_in_ecb_mode(std::string inputFileName, std::string& goodAesEcbCtxt, int& nbrOfBlockRepetition)
{
/** @brief  Take a file which contains ciphertexts represented as hex string and find the one which is encrypted with AES-128 in ECB mode
 *  @param  inputFileName   Name of file which contains ciphertext
 *  @param  goodAesEcbCtxt  Is the only ciphertext which is encrypted by AES-128 in ECB mode in the input file.
 *  @param  nbrOfBlockRepetition    Is the number of blocks which is repeted at least once
 */

    std::ifstream myInStream(inputFileName.c_str());
    if (myInStream)
    {
        std::string ctxtHexStr;

        /*1024 is a arbitrary chose number to represente the minimum of block in the cipher text */
        int minNbrOBlocks = 1024;
        int nbrOfBlocks;

        while (getline(myInStream, ctxtHexStr))
        {
            nbrOfBlocks = 0;
            nbr_of_different_block(ctxtHexStr, nbrOfBlocks);
            if (nbrOfBlocks < minNbrOBlocks)
            {
                minNbrOBlocks = nbrOfBlocks;
                goodAesEcbCtxt = ctxtHexStr;
                nbrOfBlockRepetition = ctxtHexStr.length()/32 - nbrOfBlocks;
            }
        }
    }
}