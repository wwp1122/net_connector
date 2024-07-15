#include "internet_protocol_packet.h"
#include "../json/CJsonObject.hpp"
using namespace InternetConnect;

void InternetProtocolPacket::EncodeWifiListMsg(std::string& content, const std::string& connected_wifi, const std::set<std::string>& list) {
  neb::CJsonObject sJson, subJson, listJson;
  sJson.Add("command", "wifilist");
  for (auto wifi : list) {
    listJson.Add(wifi);
  }

  subJson.Add("wifissidlist", listJson);
  subJson.Add("connectedwifi", connected_wifi);
  sJson.Add("content", subJson);
  content = sJson.ToString();
}

bool InternetProtocolPacket::DecodeWifiListMsg(const std::string& content, WifiSsidListResponse& response) {
  neb::CJsonObject sJson(content);
  neb::CJsonObject subJson, wifiListJson;
  sJson.Get("content", subJson);
  subJson.Get("wifissidlist", wifiListJson);
  for (int i = 0; i < wifiListJson.GetArraySize(); ++i) {
    std::string item;
    wifiListJson.Get(i, item);
    if (!item.empty()) {
      response.ssid_list.insert(item);
    }
  }
  subJson.Get("connectedwifi", response.connected_wifi);
  return true;
}

void InternetProtocolPacket::EncodeNetCardListMsg(std::string& content, const std::set<std::string>& list) {
  neb::CJsonObject sJson, subJson, listJson;
  sJson.Add("command", "netcardlist");
  for (auto net_card : list) {
    listJson.Add(net_card);
  }

  subJson.Add("netcarddeslist", listJson);
  sJson.Add("content", subJson);
  content = sJson.ToString();
}

bool InternetProtocolPacket::DecodeNetCardListMsg(const std::string& content, NetCardListResponse& response) {
  neb::CJsonObject sJson(content);
  neb::CJsonObject subJson, netcardListJson;
  sJson.Get("content", subJson);
  subJson.Get("netcarddeslist", netcardListJson);
  for (int i = 0; i < netcardListJson.GetArraySize(); ++i) {
    std::string item;
    netcardListJson.Get(i, item);
    if (!item.empty()) {
      response.net_card_list.insert(item);
    }
  }
  return true;
}