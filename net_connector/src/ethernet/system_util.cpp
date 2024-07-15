#include "system_util.h"

#include<atlbase.h>
#include<atlconv.h>
#include <iphlpapi.h>
#include <netcfgn.h>

#include <strsafe.h>

std::vector<NetcardInfo> SystemUtil::FindNetcard() {
  std::vector<NetcardInfo> netcards;

  PIP_ADAPTER_INFO adapter_info;
  PIP_ADAPTER_INFO adapter = NULL;

  adapter_info = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
  ULONG out_buf_len = sizeof(IP_ADAPTER_INFO);
  if (GetAdaptersInfo(adapter_info, &out_buf_len) != ERROR_SUCCESS) {
    free(adapter_info);
    adapter_info = (IP_ADAPTER_INFO*)malloc(out_buf_len);
  }
  if (GetAdaptersInfo(adapter_info, &out_buf_len) != NO_ERROR) {
    free(adapter_info);
    return netcards;
  }
  adapter = adapter_info;
  auto physical_cards = FindPhysicalNetCardFromReg();
  while (adapter)
  {
    // 仅保留物理网卡
    if (std::find(physical_cards.begin(), physical_cards.end(), adapter->AdapterName) == physical_cards.end()) {
      adapter = adapter->Next;
      continue;
    }
    NetcardInfo netcard;
    memset(netcard.name, 0, sizeof(netcard.name));
    sprintf_s(netcard.name, sizeof(netcard.name) - 1, "\\Device\\NPF_%s", adapter->AdapterName);
    sprintf_s(netcard.description, sizeof(netcard.description) - 1, adapter->Description);
    for (UINT i = 0; i < adapter->AddressLength && i < MAC_SIZE; ++i) {
      netcard.mac[i] = adapter->Address[i];
    }
    netcard.is_wireless = (adapter->Type == 71);

    adapter = adapter->Next;
    netcards.emplace_back(netcard);
  }

  free(adapter_info);
  return netcards;
}

std::vector<std::string> SystemUtil::FindPhysicalNetCardFromReg() {
  std::vector<std::string> net_cards;

  auto all_cards = FindAllNetCardFromReg();
  HKEY hkey;
  DWORD dwType = REG_SZ;
  TCHAR szData[MAX_PATH] = { 0 };
  DWORD characteristics = 0;
  DWORD size = sizeof(DWORD);
  for (auto card : all_cards) {
    std::string key = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\" + card;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
      continue;
    }

    size = sizeof(DWORD);
    dwType = REG_SZ;
    if (RegQueryValueEx(hkey, "Characteristics", NULL, &dwType, (LPBYTE)&characteristics, &size) != ERROR_SUCCESS) {
      RegCloseKey(hkey);
      continue;
    }

    if ((characteristics & NCF_PHYSICAL) != NCF_PHYSICAL) {
      RegCloseKey(hkey);
      continue;
    }

    size = MAX_PATH;
    dwType = REG_SZ;
    if (RegQueryValueEx(hkey, "NetCfgInstanceId", NULL, &dwType, (LPBYTE)szData, &size) == ERROR_SUCCESS) {
      net_cards.emplace_back(szData);
    }
    RegCloseKey(hkey);
  }
  return net_cards;
}

std::vector<std::string> SystemUtil::FindAllNetCardFromReg() {
  std::vector<std::string> net_cards;

  HKEY hkey;
  LPCTSTR subkey = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}";
  DWORD item_index = 0;
  TCHAR item_name[MAX_PATH] = { 0 };
  DWORD size = MAX_PATH;

  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
    return net_cards;
  }

  while (RegEnumKeyEx(hkey, item_index, item_name, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
    size = MAX_PATH;
    net_cards.emplace_back(item_name);
    item_index++;
  }
  RegCloseKey(hkey);
  return net_cards;
}

void SystemUtil::DebugPrintf(LPCTSTR ptzFormat, ...)
{
  va_list vlArgs;
  va_start(vlArgs, ptzFormat);
  TCHAR tzText[1024] = { 0 };
  StringCchVPrintf(tzText, sizeof(tzText), ptzFormat, vlArgs);
  va_end(vlArgs);
  OutputDebugString(tzText);
}