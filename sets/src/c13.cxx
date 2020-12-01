#include "c01.hxx"
#include "c07.hxx"
#include "c13.hxx"
#include "c09.hxx"
#include <algorithm>

std::string ltrim(const std::string& s)
{
    size_t start = s.find_first_not_of(WHITESPACE);
    return (start == std::string::npos) ? "" : s.substr(start);
}
 
std::string rtrim(const std::string& s)
{
    size_t end = s.find_last_not_of(WHITESPACE);
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}
 
std::string trim(const std::string& s)
{
    return rtrim(ltrim(s));
}

void split_string(const std::string inputStr, const char delimiter, std::vector<std::string>& tokens)
{
    std::string token;
    std::istringstream iss(inputStr);
    
    while (std::getline(iss, token, delimiter))
    {
        tokens.push_back(token);
    }
}


void parsing(const std::string urlStr, std::string& jsonStr)
{
/** @brief  Takes an encoded profile and provides its json representation
 *  @param  urlStr      A encoded string profile
 *  @param  jsonStr     A Json representation of input encoded profile
 */

    /* Trim the encoded  profile string */
    trim(urlStr);
    char delimiter = '&';
    std::vector<std::string> tokens;
    std::stringstream ss;
    
    /* construct json structure representation of elements */
    ss << "{" << std::endl;

    /* Split input string with delimitor '&' */
    split_string(urlStr, delimiter, tokens);
    for (const auto& token : tokens)
    {
        std::size_t ind = token.find('=');
        if (ind != std::string::npos)
        {
            ss << "  " << token.substr(0, ind) << ": ";
            std::string str = token.substr(ind+1, token.length() - ind);
            try
            {
                ss << std::stoi(str) << "," << std::endl;
            }
            catch (std::invalid_argument const &e)
            {
                ss << "'" << trim(str) << "'," << std::endl;
            }
        }        
    }
    /* Remove the last comma */
    ss.seekp(-2, ss.cur);
    ss << "\n}";
    jsonStr = ss.str();
}

void profile_for(const std::string emailStr, std::string& jsonStr)
{
/** @brief  Constructs a pre-defined profile, with 'uid=10' and 'role=user', from a given email and returns a json representaiton of it
 *  @param  emailStr    A email which should be involved in template profile
 *  @param  jsonStr     A json representation of the profile construct by the email.
*/
    std::size_t indEqual = emailStr.find('=');
    std::size_t indAmpersand = emailStr.find('&');

    /* Checks that the email don't contain char '&' and '=' */
    if((indEqual == std::string::npos) && (indAmpersand == std::string::npos))
    {
        std::stringstream ss;
        ss << "email=" << emailStr << "&uid=10&role=user";
        std::string urlStr = ss.str();
        parsing(urlStr, jsonStr);
    }
    else
    {
        std::cerr << "Error !!! Input email contains forbbiden charaters '&' and '='" << std::endl;
    }
    
}

void encode_profile(const std::string emailStr, std::string& encodedProfileStr)
{
/** @brief  Constructs a pre-defined profile, with 'uid=10' and 'role=user', from a given email
 *  @param  emailStr            A email which should be involved in template profile
 *  @param  encodedProfileStr   The pre-define profile construct from email.
*/
    std::size_t indEqual = emailStr.find('=');
    std::size_t indAmpersand = emailStr.find('&');

    /* Checks that the email don't contain char '&' and '=' */
    if((indEqual == std::string::npos) && (indAmpersand == std::string::npos))
    {
        encodedProfileStr = "email=" + emailStr + "&uid=10&role=user";
    }
    else
    {
        std::cerr << "Error !!! Input email contains forbbiden charaters '&' and '='" << std::endl;
    }
}

void function_A_encryption(const std::string emailStr, int& lenCiphertextArray, uint8_t*& ciphertextArray)
{
/** @brief  A function which takes an email, build a profile and encrypts it.
 *  @param  emailStr            email to encode in the profile before encryption
 *  @param  lenCiphertextArray  length of output array ciphertext
 *  @param  ciphertextArray     array which contains encrypted profile.
*/

   int blockLen = 16;

    /* Initialize the Oracle Key */
    uint8_t* consistentKeyArray = NULL;
    int lenConsistentKeyArray;
    string_to_bytes(consistentKeyStr, lenConsistentKeyArray, consistentKeyArray);

    /* Transform email as a profile */
    std::string encodedProfileStr;
    encode_profile(emailStr, encodedProfileStr);

    uint8_t* plaintextArray;
    int lenPlaintextArray;
    string_to_bytes(encodedProfileStr, lenPlaintextArray, plaintextArray);

    uint8_t* paddedPlaintext;
    int lenPaddedPlaintext;
    /* Pad plaintext until its length become a multiple of block size */
    pkcs7_padding_bytes(blockLen, plaintextArray, lenPlaintextArray, lenPaddedPlaintext, paddedPlaintext);
    /* Encryption of encoded profile */
    encrypt_aes_128_in_ecb(paddedPlaintext, lenPaddedPlaintext, 0, consistentKeyArray, lenCiphertextArray, ciphertextArray);
}

void function_B_decryption(const uint8_t* ciphertextArray, const int lenCiphertextArray, std::string& jsonStr)
{
/** @brief  Take an encrypted encoded profile, decrypts it with oracle key and returns its json representation
 *  @param  ciphertextArray         Array that contain encrypted profile
 *  @param  lenCiphertextArray      Length of ciphertext array
 *  @param  jsonStr                 The json representation of decrypted profile.
*/

    /* Initialize the Oracle Key */
    uint8_t* consistentKeyArray;
    int lenConsistentKeyArray;
    string_to_bytes(consistentKeyStr, lenConsistentKeyArray, consistentKeyArray);

    int lenPaddedPlaintext;
    uint8_t* paddedPlaintext;
    decrypt_aes_128_in_ecb(ciphertextArray, lenCiphertextArray, 0, consistentKeyArray, lenPaddedPlaintext, paddedPlaintext);

    /* remove padding added before encryption */
    uint8_t* plaintextArray;
    int lenPlaintextArray;
    pkcs7_unpadding_bytes(paddedPlaintext, lenPaddedPlaintext, lenPlaintextArray, plaintextArray);
    
    std::string plaintextStr;
    bytes_to_string(plaintextArray, lenPlaintextArray, plaintextStr);

    parsing(plaintextStr, jsonStr);

}

void ecb_cut_and_paste(const std::string emailStr, std::string& jsonStr)
{
/** @brief  Change the role of a profile to admin , given an email
 *  @param  emailStr    Email that needs to have a profile
 *  @param  jsonStr     Json representation of modified profile
*/

    int blockLen = 16;
    /*  Stage 1: get the encrypted blocks for email
        we finish with encrypted blocks for plaintext : "email=foo@bar.com"+(5+10)*" " 
    */
    int lenEmail = emailStr.length();
    std::string paddedEmailStr = emailStr;
    int r = lenEmail % blockLen;
    for (int i = 0; i < 10 + (16-r); i++)
    {
        paddedEmailStr += " ";
    }
    
    uint8_t* ciphertextArray;
    int lenCiphertextArray;
    function_A_encryption(paddedEmailStr, lenCiphertextArray, ciphertextArray);

    // We use +2 because we include block for "email="+10*" "
    int lenFirstBlockArray = (lenEmail/blockLen + 2) * blockLen;
    uint8_t* firstBlockArray = new uint8_t[lenFirstBlockArray];
    std::copy(ciphertextArray, ciphertextArray + lenFirstBlockArray, firstBlockArray);

    /* Stage 2: get uid's block */
    paddedEmailStr="";
    for (int i = 0; i < (10 + 3); i++)
        paddedEmailStr += " ";
    
    function_A_encryption(paddedEmailStr, lenCiphertextArray, ciphertextArray);
    int lenSecondBlockArray = blockLen;
    uint8_t* secondBlockArray = new uint8_t[lenSecondBlockArray];
    std::copy(ciphertextArray + blockLen, ciphertextArray + 2*blockLen, secondBlockArray);

    /* Stage 3: get block of role*/
    paddedEmailStr = "";
    for (int i = 0; i < 10; i++)
        paddedEmailStr += " ";

    paddedEmailStr += "admin";
    for (int i = 0; i < 11; i++)
        paddedEmailStr += " ";

    function_A_encryption(paddedEmailStr, lenCiphertextArray, ciphertextArray);
    int lenThirdBlockArray = blockLen;
    uint8_t* thirdBlockArray = new uint8_t[lenThirdBlockArray];
    std::copy(ciphertextArray + blockLen, ciphertextArray + 2*blockLen, thirdBlockArray);

    /* Stage 4: get last padding block */
    paddedEmailStr = "";
    for (int i = 0; i < 9; i++)
        paddedEmailStr += " ";

    function_A_encryption(paddedEmailStr, lenCiphertextArray, ciphertextArray);
    int lenFourthBlockArray = blockLen;
    uint8_t* fourthBlockArray = new uint8_t[lenFourthBlockArray];
    std::copy(ciphertextArray + lenCiphertextArray - blockLen, ciphertextArray + lenCiphertextArray, fourthBlockArray);

    /* Merge block one, two, three and four to construct false encrypted profile with role=admin */
    lenCiphertextArray = lenFirstBlockArray + lenSecondBlockArray + lenThirdBlockArray + lenFourthBlockArray;
    ciphertextArray = new uint8_t[lenCiphertextArray];
    std::copy(firstBlockArray, firstBlockArray + lenFirstBlockArray, ciphertextArray);
    std::copy(secondBlockArray, secondBlockArray + lenSecondBlockArray, ciphertextArray + lenFirstBlockArray);
    std::copy(thirdBlockArray, thirdBlockArray + lenThirdBlockArray, ciphertextArray + lenFirstBlockArray + lenSecondBlockArray);
    std::copy(fourthBlockArray, fourthBlockArray + lenFourthBlockArray, ciphertextArray + lenCiphertextArray - lenFourthBlockArray);
    
    function_B_decryption(ciphertextArray, lenCiphertextArray, jsonStr);
}