#include "lib.hxx"
#include "c04.hxx"


void detect_single_character_xor(const std::string inputFileName, std::string &outputCtxtStr, float &bestScore, uint8_t &key, std::string &outputPtxtStr)
{
    /** @brief  Takes a file which containts hex encoded strings and find single one which is encrypted by single-character XOR. 
     *  @param  inputFileName   Name of file which contains hex encode strings.
     *  @param  outputCtxtStr   Text in the input file which is encrypted with single-character XOR.
     *  @param  bestScore       The score of string which gets the best norm L1 value for every encrypted text in input file. 
     *  @param  key             Key which encrypt the text which is encrypted by single-character XOR.
     *  @param  outputPtxtStr   Decrypted text which was encrypted by single-characte XOR ans key.
     */

    bestScore = -INFINITY;
    std::ifstream myStream(inputFileName.c_str());
    
    if (myStream)
    {
        std::string ctxtStr;
        while (getline(myStream, ctxtStr))
        {
            float score;
            uint8_t tmpKey;
            std::string ptxtStr;
            
            /*Decrypt the text and if it is printable compute its score cf c3.cxx*/
            single_byte_xor_cipher(ctxtStr, score, tmpKey, ptxtStr);

            if (bestScore < score)
            {
                bestScore = score;
                key = tmpKey;
                outputCtxtStr = ctxtStr;
                outputPtxtStr = ptxtStr;
            }
        }
    }
    else
    {
        std::cout << "Error! file:" << inputFileName << "couldn't open." << std::endl;
    }
    
}