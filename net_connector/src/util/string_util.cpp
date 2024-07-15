#include "string_util.h"

#include <Windows.h>

std::string StringUtil::wstring2string(const std::wstring& wstr, unsigned int code_page) {
  std::string result;
  int len = WideCharToMultiByte(code_page, 0, wstr.c_str(), wstr.size(), NULL, 0, NULL, NULL);
  char* buffer = new char[len + 1];
  WideCharToMultiByte(code_page, 0, wstr.c_str(), wstr.size(), buffer, len, NULL, NULL);
  buffer[len] = '\0';
  result.append(buffer);
  delete[] buffer;
  return result;
}

std::wstring StringUtil::string2wstring(const std::string& str, unsigned int code_page) {
  std::wstring result;
  int len = MultiByteToWideChar(code_page, 0, str.c_str(), str.size(), NULL, 0);
  wchar_t* buffer = new wchar_t[len + 1];
  MultiByteToWideChar(code_page, 0, str.c_str(), str.size(), buffer, len);
  buffer[len] = '\0';
  result.append(buffer);
  delete[] buffer;
  return result;
}

std::wstring StringUtil::AnsiToUnicode(const std::string& ansi_str) {
  return string2wstring(ansi_str, CP_ACP);
}

std::string StringUtil::UnicdeToAnsi(const std::wstring& uncode_str) {
  return wstring2string(uncode_str, CP_ACP);
}