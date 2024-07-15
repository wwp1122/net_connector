#pragma once

#include <QtWidgets/QWidget>
#include "ui_net_connector_caller.h"
#include <windows.h>
#include <set>

class NetConnectorCaller : public QWidget
{
  Q_OBJECT

public:
  NetConnectorCaller(QWidget* parent = Q_NULLPTR);
  ~NetConnectorCaller();

  bool Init();
  bool InitDll();
  void OnNetEventCallBack(int event_type, const char*);
  void OnWifiScanResult(const char*);
  void OnEthernetScanResult(const char*);
  void OnAddDescriptionItems(const std::set<std::string>& list, const std::string& connected);

private:
  std::string GetSelectedSsid();
  void InitNet();

signals:
  void ShowResultMsg(const QString& result);

protected slots:
  void on_pushButton_connect_clicked();
  void on_pushButton_disconnect_clicked();

  void on_pushButton_switch_clicked();
  void OnShowResultMsg(const QString& result);

private:
  Ui::NetConnectorCallerClass ui;
  HMODULE internet_dll_;
  bool is_wireless_;
};
