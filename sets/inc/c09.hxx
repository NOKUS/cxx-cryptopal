#ifndef __C09_HXX__
#define __C09_HXX__

#include "lib.hxx"
#include "c01.hxx"

/** @brief  Implements PKCS#7 padding which takes a byte array as input.
 *  @param  lenBlock            The length of the block
 *  @param  plaintext           Byte array that should be padded to a multiple of lenBlock
 *  @param  lenPlaintext        Length of array to pad
 *  @param  lenPaddedPlaintext  Length of the padded array
 *  @param  paddedPlaintext     Byte array which contains input array padded with PKCS#7 padding
 */
void pkcs7_padding_bytes(const int lenBlock, const uint8_t* plaintext, const int lenPlaintext, int& lenPaddedPlaintext, uint8_t*& paddedPlaintext);

/** @brief  Implements PKCS#7 unpadding which takes a byte array as input.
 *  @param  paddedPlaintext     Byte array which contains input array padded with PKCS#7 padding
 *  @param  lenPaddedPlaintext  Length of the padded array
 *  @param  lenPlaintext        Length of array unpadded
 *  @param  plaintext           Byte array which contains plaintext unpadded
 */
void pkcs7_unpadding_bytes(const uint8_t* paddedPlaintext, const int lenPaddedPlaintext, int& lenPlaintext, uint8_t*& plaintext);

/** @brief  Implements PKCS#7 padding which takes a string as input, converts it in byte array before padding.
 *  @param  lenBlock            The length of block
 *  @param  plaintextStr        String which should be padded
 *  @param  paddedPlaintextStr  String which is padded
 */
void pkcs7_padding(const int lenBlock, const std::string plaintextStr, std::string& paddedPlaintextStr);

/** @brief  Implements PKCS#7 unpadding which takes a string as input and converts it in byte array before unpadding.
 *  @param  paddedPlaintextStr  padded string
 *  @param  plaintextStr        unpadded string
 */
void pkcs7_unpadding(const std::string paddedPlaintextStr, std::string& plaintextStr);

/** @brief  Implements PKCS#7 padding which take a string as input and pads without convert in byte array
 *  @param  lenBlock            The length of block
 *  @param  plaintextStr        String which should be padded
 *  @param  paddedPlaintextStr  String which is padded
 */
void pkcs7_padding_without_bytes(const int lenblock, const std::string plaintextStr, std::string& paddedPlaintextStr);

void pkcs7_unpadding_without_bytes(const std::string paddedPlaintextStr, std::string& plaintextStr);

#endif /*__C09_HXX__*/