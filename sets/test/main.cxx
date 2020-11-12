#include <iostream>
#include "lib.hxx"
#include "c01.hxx"
#include "c02.hxx"
#include "c03.hxx"
#include "c04.hxx"
#include "c05.hxx"
#include "c06.hxx"
#include "c07.hxx"
#include "c08.hxx"
#include "c09.hxx"
#include "c10.hxx"

using namespace std;

/* Number of Challenge to compilate */
#define TEST 10


int main()
{

   #if TEST == 01

      test_encode_to_base64();
      test_decode_from_base64();

   #elif TEST == 02
      bool isTestSuccess = test_fixed_xor();
      printf("-----------------------------------------------------\n");
      printf("Test Fixed XOR\n");
      printf("Test result is: %s.\n", (isTestSuccess ? "OK" : "KO"));
      printf("-----------------------------------------------------\n\n");

      std::string challengeInput0 = "1c0111001f010100061a024b53535009181c";
      std::string challengeInput1 = "686974207468652062756c6c277320657965";
      std::string challengeOutput;

      fixed_xor(challengeInput0, challengeInput1, challengeOutput);

      printf("Challenges / Set 1 / Challenge 2 :\n");
      std::cout << "Input 1: \t" << challengeInput0 << std::endl;
      std::cout << "Input 2: \t" << challengeInput1 << std::endl;
      std::cout << "Output: \t" << challengeOutput << std::endl;
      printf("-----------------------------------------------------\n\n");

   #elif TEST == 03

      bool isTestSuccess = test_single_byte_xor_cipher();

      printf("-----------------------------------------------------\n");
      printf("Test Single Byte XOR Cipher\n");
      printf("Test result is: %s.\n", (isTestSuccess ? "OK" : "KO"));
      printf("-----------------------------------------------------\n\n");

      std::string challengeInput = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
      std::string challengeOutput;
      uint8_t decryptionKey;
      float bestScore = -INFINITY;

      single_byte_xor_cipher(challengeInput, bestScore, decryptionKey, challengeOutput);

      printf("Challenges / Set 1 / Challenge 3 :\n");
      std::cout << "Input:  \t" << challengeInput << std::endl;
      std::cout << "Output: \t" << challengeOutput << std::endl;
      std::cout << "Best Score\t" << bestScore << std::endl;
      std::cout << "Decryption key:\t" << (int)decryptionKey << std::endl;
      printf("-----------------------------------------------------\n\n");

   #elif TEST == 04

      bool isTestSuccess = test_detect_single_character_xor();

      printf("-----------------------------------------------------\n");
      printf("Test Detect single-character XOR \n");
      printf("Test result is: %s.\n", (isTestSuccess ? "OK" : "KO"));
      printf("-----------------------------------------------------\n\n");

      std::string inputFileName = "test/texts/4.txt";
      std::string outputCtxtStr;
      std::string outputPtxtStr;
      uint8_t decryptionKey;
      float bestScore;

      detect_single_character_xor(inputFileName, outputCtxtStr, bestScore, decryptionKey, outputPtxtStr);

      printf("Challenges / Set 1 / Challenge 4 :\n");
      std::cout << "CipherText is:  \t" << outputCtxtStr << std::endl;
      std::cout << "Plaintext is: \t" << outputPtxtStr << std::endl;
      std::cout << "Best Score\t" << bestScore << std::endl;
      std::cout << "Decryption key:\t" << (int)decryptionKey << std::endl;
      printf("-----------------------------------------------------\n\n");
   
   #elif TEST == 05

      bool isTestSuccess = test_repeating_key_xor();

      printf("-----------------------------------------------------\n");
      printf("Test Implement repeating-key XOR \n");
      printf("Test result is: %s.\n", (isTestSuccess ? "OK" : "KO"));
      printf("-----------------------------------------------------\n\n");

      std::string inputStr = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
      std::string output;
      std::string key = "ICE";

      repeating_key_xor(inputStr, key, output);


      printf("Challenges / Set 1 / Challenge 5 :\n");
      std::cout << "Output is: \t" << output << std::endl;
      printf("-----------------------------------------------------\n\n");

   
   #elif TEST == 06

      printf("Challenges / Set 1/ Challenge 6:\n");
      bool isTestSuccess = test_hamming_weight();
      isTestSuccess &= test_hamming_distance();
      printf("Test Hamming weight and distance for challenge 06 : %d \n", isTestSuccess);

      std::string inputFileName = "test/texts/6.txt";
      std::string outputFileName = "test/texts/output_c06.txt";
      std::string encryptionKey;

      break_repeating_key_xor(inputFileName, encryptionKey, outputFileName);

   #elif TEST == 07

      bool isTestSuccess = test_aes_128_ecb();
      printf("-----------------------------------------------------\n");
      printf("Test Challenges / set 1 / challenge 7 \n");
      printf("Test result is: %s.\n", (isTestSuccess ? "OK" : "KO"));
      printf("-----------------------------------------------------\n\n");
      std::string inputFileName = "test/texts/7.txt";
      std::string outputFileName = "test/texts/output_c07.txt";
      std::string aesKeyStr = "YELLOW SUBMARINE";
      decryption_aes_128_in_ecb_mode(inputFileName, aesKeyStr, outputFileName);
   
   #elif TEST == 8

      printf("Challenges / Set 1/ Challenge 8:\n");
      std::string inputFileName = "test/texts/8.txt";
      std::string goodAesEcbCtxt;
      int nbrOfBlockRepetition;

      detect_aes_in_ecb_mode(inputFileName, goodAesEcbCtxt, nbrOfBlockRepetition);
      
      std::cout << "Output is: \n" << goodAesEcbCtxt << "\n" << std::endl;
      printf("There are %d repetitions of block in this ciphertext.\n\n", nbrOfBlockRepetition);

   #elif TEST == 9
   
      std::string challengeInput = "YELLOW SUBMARINE";
      std::string expectedOutput = "YELLOW SUBMARINE\x04\x04\x04\x04";
      std::string challengeOutput;
      std::string unpaddedPlaintext;

      pkcs7_padding_without_bytes(16, challengeInput, challengeOutput);
      pkcs7_unpadding_without_bytes(challengeOutput, unpaddedPlaintext);

      printf("Challenges / Set 2 / Challenge 9 :\n");
      std::cout << "Input Challenge: \t" << challengeInput << std::endl;
      std::cout << "Output Challenge: \t" << challengeOutput << std::endl;
      std::cout << "unpadded Plaintext: \t" << unpaddedPlaintext << std::endl;
      printf("-----------------------------------------------------\n\n");
   
   #elif TEST == 10

      bool isTestSuccess = test_aes_128_cbc();
      printf("-----------------------------------------------------\n");
      printf("Test Challenges / set 2 / challenge 10 \n");
      printf("Test result is: %s.\n", (isTestSuccess ? "OK" : "KO"));
      printf("-----------------------------------------------------\n\n");
      std::string inputFileName = "test/texts/10.txt";
      std::string outputFileName = "test/texts/output_c10.txt";
      std::string keyStr = "YELLOW SUBMARINE";
      std::string IVStr = "00000000000000000000000000000000";

      decrypt_cbc_text(inputFileName, keyStr, IVStr, outputFileName);

        
   #endif
}
