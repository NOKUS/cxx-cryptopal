#ifndef __C13_HXX__
#define __C13_HXX__

#include "c01.hxx"
#include "lib.hxx"

/* Consistent Key for Oracle encryption */
const std::string consistentKeyStr = std::string("YELLOW SUBMARINE");

const std::string WHITESPACE = " \n\r\t\f\v";
std::string ltrim(const std::string& s);
std::string rtrim(const std::string& s);
std::string trim(const std::string& s);

void split_string(const std::string inputStr, const char delimiter, std::vector<std::string>& tokens);

/** @brief  Takes an encoded profile and provides its json representation
 *  @param  urlStr      A encoded string profile
 *  @param  jsonStr     A Json representation of input encoded profile
 */
void parsing(const std::string UrlStr, std::string& jsonStr);

/** @brief  Constructs a pre-defined profile, with 'uid=10' and 'role=user', from a given email and returns a json representaiton of it
 *  @param  emailStr    A email which should be involved in template profile
 *  @param  jsonStr     A json representation of the profile construct by the email.
*/
void profile_for(const std::string emailStr, std::string& jsonStr);

/** @brief  Constructs a pre-defined profile, with 'uid=10' and 'role=user', from a given email
 *  @param  emailStr            A email which should be involved in template profile
 *  @param  encodedProfileStr   The pre-define profile construct from email.
*/
void encode_profile(const std::string emailStr, std::string& encodedProfileStr);

/** @brief  A function which takes an email, build a profile and encrypts it.
 *  @param  emailStr            email to encode in the profile before encryption
 *  @param  lenCiphertextArray  length of output array ciphertext
 *  @param  ciphertextArray     array which contains encrypted profile.
*/

void function_A_encryption(const std::string emailStr, int& lenCiphertextArray, uint8_t*& ciphertextArray);

/** @brief  Take an encrypted encoded profile, decrypts it with oracle key and returns its json representation
 *  @param  ciphertextArray         Array that contain encrypted profile
 *  @param  lenCiphertextArray      Length of ciphertext array
 *  @param  jsonStr                 The json representation of decrypted profile.
*/
void function_B_decryption(const uint8_t* ciphertextArray, const int lenCiphertextArray, std::string& jsonStr);

/** @brief  Change the role of a profile to admin , given an email
 *  @param  emailStr    Email that needs to have a profile
 *  @param  jsonStr     Json representation of modified profile
*/
void ecb_cut_and_paste(const std::string emailStr, std::string& jsonStr);

#endif /*__C13_HXX__*/