#pragma once
#include <string>
#include <set>
#include <vector>
#include <windows.h>
#include <wlanapi.h>
#include <functional>
#include <QTimer>

#include "../internet_manager.h"

struct WifiParas {
  std::wstring net_card_name;
  std::set<std::string> wifi_info;
  GUID guid;
  std::string connected_wifi;
};

class WifiManager : public QObject ,public InternetManager
{
  Q_OBJECT
public:
  WifiManager();
  ~WifiManager();

  bool Init(LPNetNotifyCallBack wifi_notification_cb) override;
  void Release() override;

  bool Connect(const std::string& ssid, const std::string& username, const std::string& pwd)override;
  bool Disconnect(const std::string& ssid)override;

  void OnWifiNotificationResult(const GUID& guid, int type, const std::string& error);

private:
  bool InitalHandle();
  bool ScanWifi();

  void OnScanWifiResult(const GUID& guid);

  void GetAvailableNetworkList(const GUID& guid, std::set<std::string>& info);
  std::string GetWifiListContent();

  bool GetNetCard(const std::string& ssid, WLAN_INTERFACE_INFO& card, WLAN_AVAILABLE_NETWORK& wifi);
  std::string GetConnectedWifi(const GUID& guid);
  bool SetProfile(const std::string& username, const std::string& password,
    const WLAN_INTERFACE_INFO& net_card, const WLAN_AVAILABLE_NETWORK& wlan);

protected slots:
  void OnTimerStop();

private:
  LPNetNotifyCallBack wifi_notification_cb_;
  HANDLE wlan_handle_;
  std::vector<WifiParas> paras_;
  QTimer stop_timer_;

  WLAN_INTERFACE_INFO net_card_back_;
  WLAN_AVAILABLE_NETWORK wlan_back_;
};



class WifiInfo {
public:
  WifiInfo():
    net_card_list(nullptr)
  , wlan_list(nullptr) {
  }
  ~WifiInfo() {
    if (net_card_list != nullptr) {
      WlanFreeMemory(net_card_list);
      net_card_list = nullptr;
    }
    if (wlan_list != nullptr) {
      WlanFreeMemory(wlan_list);
      wlan_list = nullptr;
    }
  }
  PWLAN_INTERFACE_INFO_LIST net_card_list;
  PWLAN_AVAILABLE_NETWORK_LIST wlan_list;
};