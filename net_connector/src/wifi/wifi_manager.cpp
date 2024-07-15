#include "wifi_manager.h"
#include "wifi_xml_util.h"
#include "../util/string_util.h"
#include "../../public/protocol/internet_protocol_packet.h"
#include "../../net_connector_define.h"


void OnNotificationCallback(PWLAN_NOTIFICATION_DATA data, PVOID context) {
  if (!context) {
    return;
  }

  WifiManager* ptr = static_cast<WifiManager*>(context);
  if (data == NULL || data->NotificationSource != WLAN_NOTIFICATION_SOURCE_ACM) {
    return;
  }

  switch (data->NotificationCode) {
  case wlan_notification_acm_connection_complete: {
    PWLAN_CONNECTION_NOTIFICATION_DATA connection = (PWLAN_CONNECTION_NOTIFICATION_DATA)data->pData;
    if (connection->wlanReasonCode == WLAN_REASON_CODE_SUCCESS) {
      return ptr->OnWifiNotificationResult(data->InterfaceGuid, data->NotificationCode,
        "");
    }
    else if (connection->wlanReasonCode == 229377) {
      return;
    }
    wchar_t reason_code_str[1024] = { 0 };
    WlanReasonCodeToString(connection->wlanReasonCode, 1024, reason_code_str, NULL);
    ptr->OnWifiNotificationResult(data->InterfaceGuid, data->NotificationCode,
      StringUtil::wstring2string(reason_code_str));
    break;
  }
  case wlan_notification_acm_scan_complete:
  case wlan_notification_acm_scan_fail:
  case wlan_notification_acm_connection_start:
  case wlan_notification_acm_connection_attempt_fail:
  case wlan_notification_acm_disconnecting:
  case wlan_notification_acm_disconnected:
    ptr->OnWifiNotificationResult(data->InterfaceGuid, data->NotificationCode, "");
  default:
    break;
  }
}

WifiManager::WifiManager()
:wlan_handle_(nullptr)
, wifi_notification_cb_(nullptr) {
  stop_timer_.setSingleShot(true);
  stop_timer_.setInterval(10000);
  QObject::connect(&stop_timer_, &QTimer::timeout, this, &WifiManager::OnTimerStop);
}
WifiManager::~WifiManager() {
  if (wlan_handle_ != nullptr) {
    WlanCloseHandle(wlan_handle_, nullptr);
  }
}


bool WifiManager::Init(LPNetNotifyCallBack wifi_notification_cb) {
  wifi_notification_cb_ = wifi_notification_cb;
  if (InitalHandle() && ScanWifi()) {
    return true;
  }
  return false;
}

void WifiManager::Release() {
  if (wlan_handle_ != nullptr) {
    WlanCloseHandle(wlan_handle_, nullptr);
  }
}

bool WifiManager::InitalHandle() {
  if (wlan_handle_) {
    return true;
  }
  DWORD version;
  if (WlanOpenHandle(WLAN_API_VERSION, NULL, &version, &wlan_handle_) != ERROR_SUCCESS) {
    wlan_handle_ = nullptr;
    return false;
  }

  if (WlanRegisterNotification(wlan_handle_, WLAN_NOTIFICATION_SOURCE_ACM, TRUE,
    (WLAN_NOTIFICATION_CALLBACK)OnNotificationCallback, this, nullptr, nullptr) != ERROR_SUCCESS) {
    WlanCloseHandle(wlan_handle_, nullptr);
    wlan_handle_ = nullptr;
    return false;
  }
  return true;
}

bool WifiManager::ScanWifi() {
  if (!wlan_handle_) {
    return false;
  }

  PWLAN_INTERFACE_INFO_LIST net_card_list = nullptr;
  if (ERROR_SUCCESS != WlanEnumInterfaces(wlan_handle_, nullptr, &net_card_list)) {
    if (net_card_list != nullptr) {
      WlanFreeMemory(net_card_list);
      net_card_list = nullptr;
    }
    return false;
  }

  for (int i = 0; i < (int)net_card_list->dwNumberOfItems; i++) { //遍历每个网卡
    WifiParas para;
    auto net_card_info = (WLAN_INTERFACE_INFO*)&net_card_list->InterfaceInfo[i];
    para.net_card_name = net_card_info->strInterfaceDescription;
    para.guid = net_card_info->InterfaceGuid;
    para.connected_wifi = GetConnectedWifi(para.guid);

    if (ERROR_SUCCESS != WlanScan(wlan_handle_, (const GUID*)(&net_card_info->InterfaceGuid), nullptr, nullptr, nullptr)) {
      continue;
    }
    GetAvailableNetworkList(para.guid, para.wifi_info);
    paras_.emplace_back(para);
    //仅处理首个无线网卡
    break;
  }

  if (net_card_list != nullptr) {
    WlanFreeMemory(net_card_list);
    net_card_list = nullptr;
  }

  //立即返回已扫描wifi列表
  if (wifi_notification_cb_) {
    wifi_notification_cb_(EVENT_WIFI_SCAN_COMPLETE, GetWifiListContent());
  }
  return true;
}

bool WifiManager::Connect(const std::string& ssid, const std::string& username, const std::string& pwd) {
  WLAN_INTERFACE_INFO card;
  WLAN_AVAILABLE_NETWORK wifi;
  if (!GetNetCard(ssid, card, wifi)) {
    wifi_notification_cb_(EVENT_WIFI_CONNECTION_COMPLETE, "WLAN连接失败: 获取无线网卡失败 " + std::to_string(GetLastError()));
    return false;
  }
  if (card.isState == wlan_interface_state_connected) {
    WlanDisconnect(wlan_handle_, &card.InterfaceGuid, NULL);
  }

  if (!SetProfile(username, pwd, card, wifi)) {
    wifi_notification_cb_(EVENT_WIFI_CONNECTION_COMPLETE, "WLAN连接失败: 设置凭证失败 " + std::to_string(GetLastError()));
    return false;
  }
  WLAN_CONNECTION_PARAMETERS wlanConnPara;
  wlanConnPara.wlanConnectionMode = wlan_connection_mode_profile;
  std::wstring ucSSID = StringUtil::string2wstring((const char*)wifi.dot11Ssid.ucSSID).c_str();
  wlanConnPara.strProfile = ucSSID.c_str();			// 指定的用户文件
  wlanConnPara.pDot11Ssid = &wifi.dot11Ssid;		//指定的SSID
  wlanConnPara.dot11BssType = wifi.dot11BssType; //网络类型
  wlanConnPara.pDesiredBssidList = NULL;
  wlanConnPara.dwFlags = 0x00000000;
  if (ERROR_SUCCESS != WlanConnect(wlan_handle_, &card.InterfaceGuid, &wlanConnPara, NULL)) {
    wifi_notification_cb_(EVENT_WIFI_CONNECTION_COMPLETE, "WLAN连接失败: WlanConnect失败 " + std::to_string(GetLastError()));
    return false;
  }
  stop_timer_.start();
  return true;
}

bool WifiManager::Disconnect(const std::string& ssid) {
  WLAN_INTERFACE_INFO card;
  WLAN_AVAILABLE_NETWORK wifi;
  if (!GetNetCard(ssid, card, wifi)) {
    wifi_notification_cb_(EVENT_WIFI_CONNECTION_COMPLETE, "WLAN注销失败: 获取无线网卡失败 " + std::to_string(GetLastError()));
    return false;
  }
  if (card.isState == wlan_interface_state_disconnected) {
    return true;
  }

  DWORD result = WlanDisconnect(wlan_handle_, &card.InterfaceGuid, NULL);
  return ERROR_SUCCESS == result;
}

void WifiManager::OnWifiNotificationResult(const GUID& guid, int type, const std::string& error) {
  if (wifi_notification_cb_ == nullptr) {
    return;
  }
  EventType event_type;
  switch ((WLAN_NOTIFICATION_ACM)type) {
  case wlan_notification_acm_scan_complete:
    event_type = EVENT_WIFI_SCAN_COMPLETE;
    OnScanWifiResult(guid);
    return wifi_notification_cb_(event_type, GetWifiListContent());
  case wlan_notification_acm_scan_fail:
    event_type = EVENT_WIFI_SCAN_FAIL;
    return wifi_notification_cb_(event_type, "WLAN扫描失败");
  case wlan_notification_acm_connection_start:
    event_type = EVENT_WIFI_CONNECTION_START;
    break;
  case wlan_notification_acm_connection_complete:
    if (stop_timer_.isActive()) {
      stop_timer_.stop();
    }
    event_type = EVENT_WIFI_CONNECTION_COMPLETE;
    if ("" == error) {
      return wifi_notification_cb_(event_type, "WLAN连接成功");
    }
    else {
      DWORD result = WlanDeleteProfile(wlan_handle_, &net_card_back_.InterfaceGuid, StringUtil::string2wstring((const char*)wlan_back_.dot11Ssid.ucSSID).c_str(), NULL);
      if (ERROR_SUCCESS != result && ERROR_NOT_FOUND != result) {
        return wifi_notification_cb_(EVENT_WIFI_CONNECTION_COMPLETE, "WLAN连接失败: 请右键无线网络，手动忘记密码");
      }
      return wifi_notification_cb_(event_type, "WLAN连接失败: " + error);
    }
  case wlan_notification_acm_connection_attempt_fail:
    event_type = EVENT_WIFI_CONNECTION_ATTEMPT_FAIL;
    return wifi_notification_cb_(event_type, "WLAN尝试连接失败");
  case wlan_notification_acm_disconnecting:
    event_type = EVENT_WIFI_DISCONNECTING;
    break;
  case wlan_notification_acm_disconnected:
    event_type = EVENT_WIFI_DISCONNECTED;
    return wifi_notification_cb_(event_type, "WLAN已断开");
  default:
    break;
  }

  return ;
}

void WifiManager::OnScanWifiResult(const GUID& guid) {
  for (auto& para : paras_) {
    if (para.guid == guid) {
      GetAvailableNetworkList(para.guid, para.wifi_info);
      para.connected_wifi = GetConnectedWifi(para.guid);
      return;
    }
  }
}

void WifiManager::GetAvailableNetworkList(const GUID& guid, std::set<std::string>& info) {
  PWLAN_AVAILABLE_NETWORK_LIST wlan_list = nullptr;
  PWLAN_AVAILABLE_NETWORK wlan = nullptr;
  if (ERROR_SUCCESS != WlanGetAvailableNetworkList(wlan_handle_, &guid, 0x00, nullptr, &wlan_list)) {
    if (wlan_list != nullptr) {
      WlanFreeMemory(wlan_list);
      wlan_list = nullptr;
    }
    return;
  }

  info.clear();
  for (int j = 0; j < wlan_list->dwNumberOfItems; ++j) {
    wlan = (PWLAN_AVAILABLE_NETWORK)&wlan_list->Network[j];
    if (0 == wlan->dot11Ssid.uSSIDLength) {
      continue;
    }
    info.insert((char*)(wlan->dot11Ssid.ucSSID));
  }
  if (wlan_list != nullptr) {
    WlanFreeMemory(wlan_list);
    wlan_list = nullptr;
  }
}

std::string WifiManager::GetWifiListContent() {
  std::set<std::string> wifi_set;
  std::string connected_wifi;
  for (auto para : paras_) {
    for (auto wifi : para.wifi_info) {
      wifi_set.insert(wifi);
    }
    if (!para.connected_wifi.empty() && connected_wifi.empty()) {
      connected_wifi = para.connected_wifi;
    }
  }
  std::string content;
  InternetConnect::InternetProtocolPacket::EncodeWifiListMsg(content, connected_wifi, wifi_set);
  return content;
}

bool WifiManager::GetNetCard(const std::string& ssid, WLAN_INTERFACE_INFO& card, WLAN_AVAILABLE_NETWORK& wifi) {
  if (!wlan_handle_) {
    return false;
  }
  WifiInfo wifi_info;
  if (ERROR_SUCCESS != WlanEnumInterfaces(wlan_handle_, nullptr, &wifi_info.net_card_list)) {
    return false;
  }

  for (int i = 0; i < (int)wifi_info.net_card_list->dwNumberOfItems; i++) {
    auto net_card = (WLAN_INTERFACE_INFO*)&wifi_info.net_card_list->InterfaceInfo[i];
    if (ERROR_SUCCESS != WlanGetAvailableNetworkList(wlan_handle_, &net_card->InterfaceGuid, 0x00, NULL, &wifi_info.wlan_list)) {
      return false;
    }
    for (int j = 0; j < wifi_info.wlan_list->dwNumberOfItems; ++j) {
      auto wlan = (PWLAN_AVAILABLE_NETWORK)&wifi_info.wlan_list->Network[j];
      if (strcmp(ssid.c_str(), (char*)wlan->dot11Ssid.ucSSID) == 0) {
        card = *net_card;
        wifi = *wlan;
        return true;
      }
    }
  }
    return false;
}

std::string WifiManager::GetConnectedWifi(const GUID& guid) {
  PWLAN_CONNECTION_ATTRIBUTES connected_wlan = NULL;
  DWORD dwSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
  WLAN_OPCODE_VALUE_TYPE opCode = wlan_opcode_value_type_invalid;
  DWORD result = WlanQueryInterface(wlan_handle_, &guid, wlan_intf_opcode_current_connection,
    NULL, &dwSize, (PVOID*)&connected_wlan, &opCode);

  if (ERROR_SUCCESS == result &&
    connected_wlan->wlanAssociationAttributes.dot11Ssid.uSSIDLength > 0) {
    return (const char*)connected_wlan->wlanAssociationAttributes.dot11Ssid.ucSSID;
  }
  return "";
}

bool WifiManager::SetProfile(const std::string& username, const std::string& password,
  const WLAN_INTERFACE_INFO& net_card, const WLAN_AVAILABLE_NETWORK& wlan) {
  std::wstring data = StringUtil::string2wstring(WifiXmlUtil::GetProfileXml(wlan));
  DWORD reason;
  DWORD result = WlanSetProfile(wlan_handle_, &net_card.InterfaceGuid, 0x00,
    data.c_str(), NULL, TRUE, NULL, &reason);

  if (result != ERROR_SUCCESS && reason != ERROR_ALREADY_EXISTS) {
    return false;
  }

  data = StringUtil::string2wstring(WifiXmlUtil::GetCredentialsXml(username, password));
  result = WlanSetProfileEapXmlUserData(wlan_handle_, &net_card.InterfaceGuid,
    StringUtil::string2wstring((const char*)(wlan.dot11Ssid.ucSSID)).c_str(), 0, data.c_str(), 0);
  if (ERROR_SUCCESS != result) {
    return false;
  }
  net_card_back_ = net_card;
  wlan_back_ = wlan;
  return true;
}


void WifiManager::OnTimerStop() {
  if (ERROR_SUCCESS != WlanDeleteProfile(wlan_handle_, &net_card_back_.InterfaceGuid, (LPCWSTR)wlan_back_.dot11Ssid.ucSSID, 0)) {
    wifi_notification_cb_(EVENT_WIFI_CONNECTION_COMPLETE, "WLAN连接失败: 请右键无线网络，手动忘记密码");
  }
  wifi_notification_cb_(EVENT_WIFI_CONNECTION_COMPLETE, "WLAN连接失败: 连接超时");
}