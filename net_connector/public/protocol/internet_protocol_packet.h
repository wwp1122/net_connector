#pragma once
#include <set>
#include <string>

namespace InternetConnect {

  struct WifiSsidListResponse {
    std::set<std::string> ssid_list;
    std::string connected_wifi;
  };

  struct NetCardListResponse {
    std::set<std::string> net_card_list;
  };

class InternetProtocolPacket
{
public:
  static void EncodeWifiListMsg(std::string& content, const std::string& connected_wifi, const std::set<std::string>& list);
  static bool DecodeWifiListMsg(const std::string& content, WifiSsidListResponse& response);

  static void EncodeNetCardListMsg(std::string& content, const std::set<std::string>& list);
  static bool DecodeNetCardListMsg(const std::string& content, NetCardListResponse& response);
};

}