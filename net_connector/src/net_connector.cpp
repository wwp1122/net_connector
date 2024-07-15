#include "net_connector.h"
#include "../public/protocol/internet_protocol_packet.h"
#include "wifi/wifi_manager.h"
#include "ethernet/ethernet_manager.h"


NetConnector::NetConnector()
  :callback_(nullptr)
  , user_data_(nullptr) {
}

NetConnector::~NetConnector() {

}

void NetConnector::SetNetEventCallBack(LPNetEventCallBack callback, void* user_data) {
  callback_ = callback;
  user_data_ = user_data;
}

void NetConnector::OnNetStatusNotification(int type, const std::string& content) {
  if (!callback_) {
    return;
  }

  return callback_(type, content.c_str(), user_data_);
}


/************************************************************************/
/* Wifi Func                                                            */
/************************************************************************/
bool NetConnector::InitWifi() {
  net_manager_.reset(new WifiManager());
  if (net_manager_->Init(std::bind(&NetConnector::OnNetStatusNotification, this,
    std::placeholders::_1, std::placeholders::_2))) {
    return true;
  }
  return false;
}

void NetConnector::DeinitWifi() {
  net_manager_.reset();
}
/************************************************************************/

/************************************************************************/
/* Ethernet Func                                                        */
/************************************************************************/
bool NetConnector::InitEthernet() {
  net_manager_.reset(new EthernetManager());
  if (net_manager_->Init(std::bind(&NetConnector::OnNetStatusNotification, this,
    std::placeholders::_1, std::placeholders::_2))) {
    return true;
  }
  return true;
}
void NetConnector::DeinitEthernet() {
  net_manager_.reset();
}
/************************************************************************/

bool NetConnector::Connect(const char* ssid, const char* username,
  const char* pwd) {
  if (!net_manager_) {
    return false;
  }
  return net_manager_->Connect(ssid, username, pwd);
}

bool NetConnector::Disconnect(const char* ssid) {
  if (!net_manager_) {
    return false;
  }
  return net_manager_->Disconnect(ssid);
}
