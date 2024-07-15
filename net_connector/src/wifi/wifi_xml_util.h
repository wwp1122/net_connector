#pragma once
#include <string>
#include <windows.h>
#include <wlanapi.h>
class WifiXmlUtil
{
public:
  static std::string GetProfileXml(const WLAN_AVAILABLE_NETWORK& pNet);
  static std::string GetCredentialsXml(const std::string& username, const std::string& password);

  struct WifiParam {
    std::string name;
    std::string ssid;
    std::string connection_type;
    std::string authentication;
    std::string encryption;
  };
private:
  static bool GetWlanParam(const WLAN_AVAILABLE_NETWORK& Net, WifiParam* param);
};

