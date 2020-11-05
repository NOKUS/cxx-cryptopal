#include "c05.hxx"
#include "test_c05.hxx"

bool test_repeating_key_xor()
{
    std::string inputStr = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    std::string output;
    std::string key = "ICE";

    repeating_key_xor(inputStr, key, output);

    std::string expectedOutput = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    return (output == expectedOutput);
}