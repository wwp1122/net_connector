#ifndef STRING_UTIL_H_
#define STRING_UTIL_H_

#include <string>
#include <vector>

#define CODEPAGE_GB2312		936
#define CODEPAGE_BIG5		  950

class StringUtil{
 public:
   static std::string wstring2string(const std::wstring& wstr, unsigned int code_page = CODEPAGE_GB2312);
   static std::wstring string2wstring(const std::string& str, unsigned int code_page = CODEPAGE_GB2312);;

   static std::wstring AnsiToUnicode(const std::string& ansi_str);
   static std::string UnicdeToAnsi(const std::wstring& uncode_str);

};


#endif // STRING_UTIL_H_