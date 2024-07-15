#pragma once
#include <unordered_map>

#include "../internet_manager.h"
#include "eap.h"
#include "../util/net_card_util.h"

class EthernetManager : public InternetManager
{
public:
  EthernetManager();
  ~EthernetManager();

  bool Init(LPNetNotifyCallBack notification_cb) override;
  void Release() override;

  bool Connect(const std::string&, const std::string&, const std::string&) override;
  bool Disconnect(const std::string&) override;

private:
  void OnEthernetConnectResult(int type, const std::string& content);
  ConnectInfo GetNetCardInfoByName(const std::string& name) const;
  std::string GetEthernetListContent() const;

private:
  LPNetNotifyCallBack eth_notification_cb_;
  Eap eap_;
  std::unordered_map<std::string, NetcardInfo> net_cards_;
};

