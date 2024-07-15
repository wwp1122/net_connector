#pragma once
#include <vector>
#include <string>
#include <windows.h>

#include "global.h"

struct NetcardInfo {
  char name[NET_CARD_NAME_MAX_LENGTH];
  char description[NET_CARD_DESCRIPTION_MAX_LENGTH];
  u_char mac[MAC_SIZE];
  bool is_wireless;
};

class SystemUtil {
public:
  static std::vector<NetcardInfo> FindNetcard();

  static void DebugPrintf(LPCTSTR ptzFormat, ...);

private:
  static std::vector<std::string> FindPhysicalNetCardFromReg();
  static std::vector<std::string> FindAllNetCardFromReg();
};

inline std::string BaseName(const std::string& filename) {
  int pos = filename.rfind('\\');
  if (pos == std::string::npos) {
    return filename;
  }
  return filename.substr(pos + 1);
}

#define PATCHLOG( fmt, ...) SystemUtil::DebugPrintf((std::string("PATCHLOG:<%s:%s:%d>") + fmt).c_str(),__func__,BaseName(__FILE__).c_str(), __LINE__, ##__VA_ARGS__);

