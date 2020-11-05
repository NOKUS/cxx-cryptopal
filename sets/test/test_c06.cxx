#include "c06.hxx"
#include "test_c06.hxx"

bool test_hamming_weight()
{
    uint8_t challenge1 = 0b00011101;
    uint8_t challenge2 = 0b11101000;
    uint8_t challenge3 = 0b00000000;
    uint8_t challenge4 = 0b01100100;

    int lenChallenge1 = 1;
    int lenChallenge2 = 1;
    int lenChallenge3 = 1;
    int lenChallenge4 = 1;

    int output1;
    int output2;
    int output3;
    int output4;

    hamming_weight(&challenge1, lenChallenge1, output1);
    hamming_weight(&challenge2, lenChallenge2, output2);
    hamming_weight(&challenge3, lenChallenge3, output3);
    hamming_weight(&challenge4, lenChallenge4, output4);

    int expectedOutput1 = 4;
    int expectedOutput2 = 4;
    int expectedOutput3 = 0;
    int expectedOutput4 = 3;

    return  (expectedOutput1 == output1) &&
            (expectedOutput2 == output2) &&
            (expectedOutput3 == output3) &&
            (expectedOutput4 == output4);
}

bool test_hamming_distance()
{
    /* Challenges */
    uint8_t input01 = 0b00001111;
    uint8_t input02 = 0b01011101;

    uint8_t input11 = 0b01101011;
    uint8_t input12 = 0b01001001;
    int lenInput01 = 1;
    int lenInput02 = 1;
    int lenInput11 = 1;
    int lenInput12 = 1;

    std::string strChallenge0 = "this is a test";
    std::string strChallenge1 = "wokka wokka!!!";

    uint8_t* input03;
    uint8_t* input13;
    int lenInput03;
    int lenInput13;

    string_to_bytes(strChallenge0, lenInput03, input03);
    string_to_bytes(strChallenge1, lenInput13, input13);
    
    
    int output0;
    int output1;
    int output2;
    hamming_distance(&input01, lenInput01, &input11, lenInput11, output0);
    hamming_distance(&input02, lenInput02, &input12, lenInput12, output1);
    hamming_distance(input03, lenInput03, input13, lenInput13, output2);

    int expectedOutput0 = 3;
    int expectedOutput1 = 2;
    int expectedOutput2 = 37;

    return  (expectedOutput0 == output0) && 
            (expectedOutput1 == output1) && 
            (expectedOutput2 == output2);
}