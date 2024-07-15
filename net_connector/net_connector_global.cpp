#include <functional>
#include <memory>
#include "net_connector_global.h"

#include "./src/net_connector.h"

static std::unique_ptr<NetConnector> net_manager_ = nullptr;

bool __stdcall NetConnectorWifiInit() {
  if (!net_manager_) {
    return false;
  }

  return net_manager_->InitWifi();
}

bool __stdcall NetConnectorWifiDeInit() {
  if (!net_manager_) {
    return false;
  }
  net_manager_->DeinitWifi();
  return true;
}

bool __stdcall NetConnectorEthernetInit() {
  if (!net_manager_) {
    return false;
  }

  return net_manager_->InitEthernet();
}

bool __stdcall NetConnectorEthernetDeInit() {
  if (!net_manager_) {
    return false;
  }
  net_manager_->DeinitEthernet();
  return true;
}

bool __stdcall NetConnectorNetConnect(const char* ssid, const char* username, const char* pwd) {
  if (!net_manager_) {
    return false;
  }
  return net_manager_->Connect(ssid, username, pwd);
}

bool __stdcall NetConnectorNetDisconnect(const char* ssid) {
  if (!net_manager_) {
    return false;
  }
  return net_manager_->Disconnect(ssid);
}

void __stdcall NetConnectorSetNetEventCallBack(LPNetEventCallBack callback, void* user_data) {
  if (!net_manager_) {
    net_manager_.reset(new NetConnector);
  }
  net_manager_->SetNetEventCallBack(callback, user_data);
}