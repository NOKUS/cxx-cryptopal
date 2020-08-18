#include "c04.hxx"
#include "test_c04.hxx"

bool test_detect_single_character_xor()
{
    /* input file */
    std::string inputFileName = "/home/donald/Documents/Tutoriel/cryptopal/set1/test/texts/4.txt";
    std::string outputCtxtStr;
    std::string outputPtxtStr;
    uint8_t key;
    float bestScore;

    detect_single_character_xor(inputFileName, outputCtxtStr, bestScore, key, outputPtxtStr);

    return true;
}