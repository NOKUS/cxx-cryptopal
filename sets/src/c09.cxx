#include "c09.hxx"


void pkcs7_padding_bytes(const int lenBlock, const uint8_t* plaintext, const int lenPlaintext, int& lenPaddedPlaintext, uint8_t*& paddedPlaintext)
{
/** @brief  Implements PKCS#7 padding which takes a byte array as input.
 *  @param  lenBlock            The length of the block
 *  @param  plaintext           Byte array that should be padded to a multiple of lenBlock
 *  @param  lenPlaintext        Length of array to pad
 *  @param  lenPaddedPlaintext  Length of the padded array
 *  @param  paddedPlaintext     Byte array which contains input array padded with PKCS#7 padding
 */
    int lenOffsetBytes = lenBlock - (lenPlaintext % lenBlock);
    lenPaddedPlaintext = lenPlaintext + lenOffsetBytes;
    paddedPlaintext = new uint8_t[lenPlaintext + lenOffsetBytes];

    for (int i = 0; i < lenPlaintext; i++)
        paddedPlaintext[i] = plaintext[i];
    
    for (int i = lenPlaintext; i < lenPaddedPlaintext; i++)
        paddedPlaintext[i] = lenOffsetBytes;    
}

void pkcs7_unpadding_bytes(const uint8_t* paddedPlaintext, const int lenPaddedPlaintext, int& lenPlaintext, uint8_t*& plaintext)
{
/** @brief  Implements PKCS#7 unpadding which takes a byte array as input.
 *  @param  paddedPlaintext     Byte array which contains input array padded with PKCS#7 padding
 *  @param  lenPaddedPlaintext  Length of the padded array
 *  @param  lenPlaintext        Length of array unpadded
 *  @param  plaintext           Byte array which contains plaintext unpadded
 */
    lenPlaintext = lenPaddedPlaintext - (int)paddedPlaintext[lenPaddedPlaintext - 1];
    plaintext = new uint8_t[lenPlaintext];

    for (int i = 0; i < lenPlaintext; i++)
        plaintext[i] = paddedPlaintext[i];
    
}

void pkcs7_padding(const int lenblock, const std::string plaintextStr, std::string& paddedPlaintextStr)
{
/** @brief  Implements PKCS#7 padding which takes a string as input, converts it in byte array before padding.
 *  @param  lenBlock            The length of block
 *  @param  plaintextStr        String which should be padded
 *  @param  paddedPlaintextStr  String which is padded
 */

    int lenPlaintext;
    uint8_t* plaintext;
    string_to_bytes(plaintextStr, lenPlaintext, plaintext);
    
    int lenPaddedPlaintext;
    uint8_t* paddedPlaintext;
    pkcs7_padding_bytes(lenblock, plaintext, lenPlaintext, lenPaddedPlaintext, paddedPlaintext);
    
    bytes_to_string(paddedPlaintext, lenPaddedPlaintext, paddedPlaintextStr);
}

void pkcs7_unpadding(const std::string paddedPlaintextStr, std::string& plaintextStr)
{
/** @brief  Implements PKCS#7 unpadding which takes a string as input and converts it in byte array before unpadding.
 *  @param  paddedPlaintextStr  padded string
 *  @param  plaintextStr        unpadded string
 */
    int lenPaddedPlaintext;
    uint8_t* paddedPlaintext;
    string_to_bytes(paddedPlaintextStr, lenPaddedPlaintext, paddedPlaintext);

    int lenPlaintext;
    uint8_t* plaintext;
    pkcs7_unpadding_bytes(paddedPlaintext, lenPaddedPlaintext, lenPlaintext, plaintext);

    bytes_to_string(plaintext, lenPlaintext, plaintextStr);
}

void pkcs7_padding_without_bytes(const int lenBlock, const std::string plaintextStr, std::string& paddedPlaintextStr)
{
/** @brief  Implements PKCS#7 padding which take a string as input and pads without convert in byte array
 *  @param  lenBlock            The length of block
 *  @param  plaintextStr        String which should be padded
 *  @param  paddedPlaintextStr  String which is padded
 */

    int lenPlaintext = plaintextStr.length();
    int lenOffsetBytes = lenBlock - (lenPlaintext % lenBlock);
    paddedPlaintextStr = plaintextStr;

    std::stringstream stream;
    stream << "\\x" << std::setfill ('0') << std::setw(sizeof(char)*2) << std::hex << lenOffsetBytes;

    for (int i = 0; i < lenOffsetBytes; i++)
    {
        paddedPlaintextStr += stream.str();
    }    
}

void pkcs7_unpadding_without_bytes(const std::string paddedPlaintextStr, std::string& plaintextStr)
{
/** @brief  Implements PKCS#7 unpadding which takes a string as input and converts it in byte array before unpadding.
 *  @param  paddedPlaintextStr  padded string
 *  @param  plaintextStr        unpadded string
 */
    int len = paddedPlaintextStr.length();
    int lenPadding = std::stoi(paddedPlaintextStr.substr(len-2, 2), nullptr, 16);
    /* As padding has template \xyy, we multiply the padding length by 4 to get the realy length for this padding method of string*/
    plaintextStr = paddedPlaintextStr.substr(0, len - (4*lenPadding));
}