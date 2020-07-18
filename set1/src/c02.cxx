#include "c02.hxx"


void bytes_array_fixed_xor(const uint8_t* input0, const int lenInput0, \
const uint8_t* input1, const int lenInput1, int &lenOutput, uint8_t* &output)
{
    assert(lenInput0 == lenInput1);
    lenOutput = lenInput0;
    output = new uint8_t[lenOutput];

    for (int i = 0; i < lenOutput; i++)
    {
        output[i] = input0[i] ^ input1[i];
    }
    
}

void fixed_xor(const std::string &inputStr0, const std::string &inputStr1, std::string &outputStr)
{
    uint8_t *input0;
    uint8_t *input1;
    uint8_t *output;
    int lenInput0;
    int lenInput1;
    int lenOutput;

    hex_string_to_hex_array(inputStr0, lenInput0, input0);
    hex_string_to_hex_array(inputStr1, lenInput1, input1);

    bytes_array_fixed_xor(input0, lenInput0, input1, lenInput1, lenOutput, output);

    hex_array_to_hex_string(output, lenOutput, outputStr);

}
