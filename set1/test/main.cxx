#include <iostream>
#include "lib.hxx"
#include "c01.hxx"
#include "c02.hxx"

using namespace std;


int main()
{
   string TEST ="C02";
   if (TEST == "C01")
   {

      test_encode_to_base64();
      test_decode_from_base64();
   }
   else if (TEST == "C02")
   {
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

   }
}
