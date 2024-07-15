#include "net_card_util.h"

#include <iphlpapi.h>
#include <netcfgn.h>
#include "string_util.h"

std::vector<NetcardInfo> NetCardUtil::FindPhysicalNetcardInfo() {
  std::vector<NetcardInfo> netcards;

  ULONG out_buf_len = 0;
  DWORD ret = 0;
  PIP_ADAPTER_ADDRESSES adapter_address = NULL;
  if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_address, &out_buf_len) == ERROR_BUFFER_OVERFLOW) {
    adapter_address = (IP_ADAPTER_ADDRESSES*)malloc(out_buf_len);
    if (adapter_address == NULL) {
      OutputDebugString("Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
      return netcards;
    }
  }

  if ((ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_address, &out_buf_len)) != NO_ERROR) {
    OutputDebugString("GetAdaptersAddresses failed with error %d\n");
    if (adapter_address != NULL) {
      free(adapter_address);
    }
    return netcards;
  }

  auto physical_cards = FindPhysicalNetCardFromReg();
  PIP_ADAPTER_ADDRESSES current_address = adapter_address;
  while (current_address) {
    // 仅保留物理网卡
    if (std::find(physical_cards.begin(), physical_cards.end(), current_address->AdapterName) == physical_cards.end()) {
      current_address = current_address->Next;
      continue;
    }
    NetcardInfo netcard;
    memset(netcard.name, 0, sizeof(netcard.name));
    sprintf_s(netcard.name, sizeof(netcard.name) - 1, "%s", current_address->AdapterName);
    std::string friendly_name = StringUtil::wstring2string(current_address->FriendlyName, CP_UTF8);
    sprintf_s(netcard.friendly_name, sizeof(netcard.friendly_name) - 1, friendly_name.c_str());
    for (UINT i = 0; i < current_address->PhysicalAddressLength && i < MAC_SIZE; ++i) {
      netcard.mac[i] = current_address->PhysicalAddress[i];
    }

    netcard.is_connected = (IfOperStatusUp == current_address->OperStatus);
    netcard.is_ethernet = (IF_TYPE_ETHERNET_CSMACD == current_address->IfType);
    // ipv4
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = current_address->FirstUnicastAddress;
    while (pUnicast) {
      std::string ipv4;
      ipv4 += std::to_string((unsigned char)pUnicast->Address.lpSockaddr->sa_data[2]);
      ipv4 += '.';
      ipv4 += std::to_string((unsigned char)pUnicast->Address.lpSockaddr->sa_data[3]);
      ipv4 += '.';
      ipv4 += std::to_string((unsigned char)pUnicast->Address.lpSockaddr->sa_data[4]);
      ipv4 += '.';
      ipv4 += std::to_string((unsigned char)pUnicast->Address.lpSockaddr->sa_data[5]);
      if ("0.0.0.0" == ipv4) {
        pUnicast = pUnicast->Next;
        continue;
      }
      netcard.ipv4_vec.emplace_back(ipv4);
      pUnicast = pUnicast->Next;
    }
    netcards.emplace_back(netcard);
    current_address = current_address->Next;
  }

  if (adapter_address != NULL) {
    free(adapter_address);
  }
  return netcards;
}


std::vector<std::string> NetCardUtil::FindPhysicalNetCardFromReg() {
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

std::vector<std::string> NetCardUtil::FindAllNetCardFromReg() {
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

/*bool NetCardUtil::GetAdapterState(DWORD index) {
  MIB_IFROW Info;
  memset(&Info, 0, sizeof(MIB_IFROW));
  Info.dwIndex = index;
  if (GetIfEntry(&Info) != NOERROR) {
    printf("ErrorCode = %lu\n", GetLastError());
    return true;
  }

  if (Info.dwOperStatus == IF_OPER_STATUS_OPERATIONAL
    || Info.dwOperStatus == IF_OPER_STATUS_CONNECTED) {
    return true;
  }

  return false;
}*/