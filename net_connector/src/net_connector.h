#pragma once
#include <string>
#include <memory>
#include "internet_manager.h"
#include "../net_connector_define.h"

class NetConnector
{
public:
  NetConnector();
  ~NetConnector();
  void SetNetEventCallBack(LPNetEventCallBack callback, void* user_data);

  bool InitWifi();
  void DeinitWifi();

  bool InitEthernet();
  void DeinitEthernet();

  bool Connect(const char* name, const char* username, const char* pwd);
  bool Disconnect(const char* name);
protected:
  void OnNetStatusNotification(int type, const std::string& content);

private:
  std::unique_ptr<InternetManager> net_manager_;
  LPNetEventCallBack callback_;
  void* user_data_;
};

