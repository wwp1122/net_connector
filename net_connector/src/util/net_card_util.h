#pragma once
#include <vector>
#include <string>
#include <winsock2.h>
#include <windows.h>

//define size
#define NET_CARD_NAME_MAX_LENGTH 256
#define NET_CARD_DESCRIPTION_MAX_LENGTH 256
#define MAC_SIZE 6
#define IPV4_SIZE 4

struct NetcardInfo {
  char name[NET_CARD_NAME_MAX_LENGTH];
  char friendly_name[NET_CARD_DESCRIPTION_MAX_LENGTH];
  unsigned char mac[MAC_SIZE];
  bool is_connected;
  bool is_ethernet;
  std::vector<std::string> ipv4_vec;
};

class NetCardUtil {
public:
  static std::vector<NetcardInfo> FindPhysicalNetcardInfo();

private:
  static std::vector<std::string> FindPhysicalNetCardFromReg();
  static std::vector<std::string> FindAllNetCardFromReg();
  //static bool GetAdapterState(DWORD index);
};

