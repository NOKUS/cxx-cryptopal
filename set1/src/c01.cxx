#include "c01.hxx"

void string_to_hex(const std::string &input, uint8_t* &output, int& lenOutput)
{
    assert((input.size() % 2) == 0);

    lenOutput = input.size()/2;
    output = new uint8_t[lenOutput];

    for (int i = 0; i < lenOutput; i++)
    {
        output[i] = std::strtol(input.substr(2*i, 2).c_str(), NULL, 16);
    }
}


void hex_to_string(const uint8_t* input, const int lenInput, std::string &output)
{
    std::ostringstream ss;

    for (int i = 0; i < lenInput; i++)
    {
        ss <<  std::hex << std::setfill('0') << std::setw(2) << (int)input[i];
    }
    output = ss.str();
    ss.clear();    
}

void base64_padding(const uint8_t* input, const int lenInput, std::string& output)
{
    uint8_t b0, b1, b2;
    std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    switch (lenInput%3)
    {
        case 1 :            
            b0 = (input[lenInput - 1] >> 2) & 0b00111111;
            b1 = ((input[lenInput - 1] & 0b00000011) << 4) & 0b00110000;
            
            output += alphabet[b0];
            output += alphabet[b1];
            output += "=";
            break;
        case 2 :
            b0 = (input[lenInput - 2] >> 2) & 0b00111111;
            b1 = ((input[lenInput - 2] & 0b00000011) << 4) ^ ((input[lenInput - 1] >> 4) & 0b00001111);
            b2 = ((input[lenInput - 1] & 0b00001111) << 2) & 0b00111100;

            output += alphabet[b0];
            output += alphabet[b1];
            output += alphabet[b2];
            output += "=";
            break;
        default:
            break;
    }
}


void convert_to_base64(const uint8_t* threeOctet, std::string& fourB64Char)
{
    std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint8_t b0, b1, b2, b3;
    b0 = (threeOctet[0] >>2) & 0b00111111;
    b1 = ((threeOctet[0] & 0b00000011) << 4) ^ ((threeOctet[1] >> 4) & 0b00001111);
    b2 = ((threeOctet[1] & 0b00001111) << 2) ^ ((threeOctet[2] >> 6) & 0b00000011);
    b3 = threeOctet[2] & 0b00111111;
    
    fourB64Char += alphabet[b0];
    fourB64Char += alphabet[b1];
    fourB64Char += alphabet[b2];
    fourB64Char += alphabet[b3];
}

void hex_to_base64(const uint8_t* input, const int lenInput, base64& output)
{
    int regularLen;
    regularLen = lenInput - (lenInput % 3);

    for (int i = 0; i < regularLen; i += 3)
        convert_to_base64(input + i, output);

    base64_padding(input, lenInput, output);
}

void inv_convert_to_base64(const std::string &fourB64Char, const int i, const int index, uint8_t* &threeOctet)
{
    std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint8_t b0, b1, b2, b3;
    b0 = (uint8_t)alphabet.find(fourB64Char[i+0]);
    b1 = (uint8_t)alphabet.find(fourB64Char[i+1]);
    b2 = (uint8_t)alphabet.find(fourB64Char[i+2]);
    b3 = (uint8_t)alphabet.find(fourB64Char[i+3]);

    threeOctet[index+0] = ((b0 & 0b00111111) << 2) ^ ((b1 >> 4) & 0b00000011);
    threeOctet[index+1] = ((b1 & 0b00001111) << 4) ^ ((b2 >> 2) & 0b00001111);
    threeOctet[index+2] = ((b2 << 6) & 0b11000000) ^ (b3 & 0b00111111);
}

void get_len_padding(const base64 &input, int & len_padding)
{
    len_padding = 0;
    int n = input.size();

    if (input[n-1] == '=')
    {
        len_padding++;
        if (input[n-2] == '=')
            len_padding++;        
    }
    
    
}

void base64_unpadding(const base64 &input, const int index, uint8_t* &output)
{
    int n = input.size();
    uint8_t b0, b1, b2;
    std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    b0 = (uint8_t)alphabet.find(input[n-4]);
    b1 = (uint8_t)alphabet.find(input[n-3]);


    if (input[n-1] == '=')
    {
        if (input[n-2] == '=')
        {
            output[index] = ((b0 & 0b00111111) << 2) ^ ((b1 & 0b00110000) >> 4);
        }
        b2 = (uint8_t)alphabet.find(input[n-2]);
        output[index] = ((b0 & 0b00111111) << 2) ^ ((b1 & 0b00110000) >> 4);
        output[index + 1] = ((b1 & 0b00001111) << 4) ^ ((b2 &0b00111100) >> 2);
    }
    
}

void base64_to_hex(const base64 &input, int& lenOutput, uint8_t* &output)
{
    int regularLen = input.size();
    int n = regularLen;
    
    // the base64 string which end with "=" means it was padded.
    if (input[n-1] == '=')
    {
        regularLen -= 4;
    }

    int len_padding;
    get_len_padding(input, len_padding);
    lenOutput = (regularLen*3)/4 + ((3-len_padding)%3);
    output = new uint8_t[lenOutput];

    int index = 0;
    for (int i = 0; i < regularLen; i += 4, index +=3)
    {
        inv_convert_to_base64(input, i, index, output);
    }

    base64_unpadding(input, index, output);        
}
