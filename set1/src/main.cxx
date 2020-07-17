#include <iostream>
#include "c01.hxx"

using namespace std;


int main()
{
    
   string input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
   uint8_t *output, *output2;
   base64 b64_str;
   string str_output;
   int n;
   string_to_hex(input, n, output);
   hex_to_base64(output, n, b64_str);

   cout << input << endl;
   cout << b64_str << endl;
   base64_to_hex(b64_str, n, output2);
   hex_to_string(output2, n, str_output);
   cout << str_output << endl;
   
/*   
   for(int i = 0; i < n; i++)
        printf("%x", output[i]);
   printf("\n");
   cout << input << endl;

   string output2;
   hex_to_string(output, n, output2);
   cout << output2 << endl;
*/  
}
