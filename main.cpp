
#include </Users/banana/Documents/Workspace/md5.hh>
#include </Users/banana/Documents/Workspace/sha1.hh>
#include <iostream>
#include <sstream>

using namespace std;

int main(int argc, const char *argv[])
{
          // Any kind of data example data types
          struct
          {
                    char bytes[100];
                    int something;
                    unsigned long whatever;
          } data;

          /////////////////////////////////////////////////////////////
          // SHA1, SHA512 and MD5 static functions return the checksum
          // as hex string.

          cout << "//////////////////////" << endl;

          // Strings
          // Mã hoá văn bản bằng func SHA1
          // Nguồn nhập
          string ss1;
          cin >> ss1;

          // std::stringstream ss1("SHA of std::stringstream");
          cout << sw::sha1::calculate(ss) << endl;

          // Mã hoá văn bản bằng func SHA1
          // Nguồn nhập
          string ss2;
          cin >> ss2;
          std::stringstream ss2("SHA of std::stringstream");
          cout << sw::md5::calculate(ss2) << endl;

          // etc, etc.
          return 0;
}