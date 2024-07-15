#pragma once
#include "net_connector_define.h"

bool __stdcall NetConnectorWifiInit();
typedef bool(__stdcall* NetConnectorWifiInitFunc)();

bool __stdcall NetConnectorWifiDeInit();
typedef bool(__stdcall* NetConnectorWifiDeInitFunc)();

bool __stdcall NetConnectorEthernetInit();
typedef bool(__stdcall* NetConnectorEthernetInitFunc)();

bool __stdcall NetConnectorEthernetDeInit();
typedef bool(__stdcall* NetConnectorEthernetDeInitFunc)();

bool __stdcall NetConnectorNetConnect(const char* ssid, const char* username, const char* pwd);
typedef bool(__stdcall* NetConnectorNetConnectFunc)(const char* ssid, const char* username, const char* pwd);

bool __stdcall NetConnectorNetDisconnect(const char* ssid);
typedef bool(__stdcall* NetConnectorNetDisconnectFunc)(const char* ssid);

void __stdcall NetConnectorSetNetEventCallBack(LPNetEventCallBack callback, void* user_data);
typedef void(__stdcall* NetConnectorSetNetEventCallBackFunc)(LPNetEventCallBack callback, void* user_data);
