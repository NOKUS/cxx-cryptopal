#ifndef __C02_HXX__
#define __C02_HXX__

#include "lib.hxx"
#include "c01.hxx"

void bytes_array_fixed_xor(const uint8_t* input0, const int lenInput0, 
    const uint8_t* input1, const int lenInput1, int &lenOutput, uint8_t* &output);

void fixed_xor(const std::string &inputStr0, const std::string &inputStr1, std::string &outputStr);

#endif /* __C02_HXX__*/