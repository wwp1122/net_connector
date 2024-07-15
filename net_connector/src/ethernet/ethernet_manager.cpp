#include "ethernet_manager.h"
#include <set>
#include "../../net_connector_define.h"
#include "../../public/protocol/internet_protocol_packet.h"

EthernetManager::EthernetManager()
  :eth_notification_cb_(nullptr) {
  auto net_cards = NetCardUtil::FindPhysicalNetcardInfo();
  for (auto card : net_cards) {
    if (card.is_ethernet) {
      net_cards_[card.friendly_name] = card;
    }
  }
}

EthernetManager::~EthernetManager() {
}

bool EthernetManager::Init(LPNetNotifyCallBack notification_cb) {
  eth_notification_cb_ = notification_cb;
  eth_notification_cb_(EVENT_ETH_LIST_ACHIEVE, GetEthernetListContent());
  eap_.SetResultCallBack(std::bind(&EthernetManager::OnEthernetConnectResult,
    this, std::placeholders::_1, std::placeholders::_2));
  return true;
}

void EthernetManager::Release() {
  eap_.Clear();
}

bool EthernetManager::Connect(const std::string& net_card_name, const std::string& username, const std::string& pwd) {
  ConnectInfo info = GetNetCardInfoByName(net_card_name);
  info.username = username;
  info.password = pwd;
  info.disconnect = false;

  return eap_.Connect(info);
}

bool EthernetManager::Disconnect(const std::string& net_card_name) {
  ConnectInfo info = GetNetCardInfoByName(net_card_name);
  info.disconnect = true;

  eap_.Disconnect(info);
  return true;
}

void EthernetManager::OnEthernetConnectResult(int type, const std::string& content) {
  switch ((EventType)type) {
  case EVENT_ETH_CONNECTION_COMPLETE:
    return eth_notification_cb_(EVENT_ETH_CONNECTION_COMPLETE, content);
  case EVENT_ETH_CONNECTION_FAIL:
    return eth_notification_cb_(EVENT_ETH_CONNECTION_FAIL, content);
  case EVENT_ETH_CONNECTION_TIMEOUT:
    return eth_notification_cb_(EVENT_ETH_CONNECTION_TIMEOUT, content);
  case EVENT_ETH_LOGOFF_SUCCESS:
    return eth_notification_cb_(EVENT_ETH_LOGOFF_SUCCESS, content);
  case EVENT_ETH_LOGOFF_TIMEOUT:
    return eth_notification_cb_(EVENT_ETH_LOGOFF_TIMEOUT, content);
  default:
    break;
  }
}

ConnectInfo EthernetManager::GetNetCardInfoByName(const std::string& name) const {
  ConnectInfo info;
  for (auto net_card : net_cards_) {
    if (net_card.first == name) {
      sprintf_s(info.network_card, sizeof(info.network_card), net_card.second.name);
      for (int i = 0; i < MAC_SIZE; ++i) {
        info.mac[i] = net_card.second.mac[i];
      }
      return info;
    }
  }
  return info;
}

std::string EthernetManager::GetEthernetListContent() const {
  std::set<std::string> ethernet_list;
  for (auto net_card : net_cards_) {
    ethernet_list.insert(net_card.first);
  }
  std::string content;
  InternetConnect::InternetProtocolPacket::EncodeNetCardListMsg(content, ethernet_list);
  return content;
}