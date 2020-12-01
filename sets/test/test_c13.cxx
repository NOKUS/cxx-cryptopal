#include "c01.hxx"
#include "c13.hxx"
#include "test_c13.hxx"

bool test_parsing_routine()
{
    bool boolean = true;

    
      std::string emailStr = "foo@bar.com&admin=root";
      std::string jsonStr = "";
      profile_for(emailStr, jsonStr);
      boolean &= (jsonStr == "");

    /* Test functions which encrypts and decrypts specific profiles */
    emailStr = "foo@bar.com";
    std::string jsonStr1 = "";

    uint8_t* ciphertextArray;
    int lenCiphertextArray;
    function_A_encryption(emailStr, lenCiphertextArray, ciphertextArray);
    function_B_decryption(ciphertextArray, lenCiphertextArray, jsonStr1);
    
    std::string jsonStr2 =  "";
    profile_for(emailStr, jsonStr2);
    boolean &= (jsonStr1 == jsonStr2);

    return boolean;
}