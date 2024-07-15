#include "net_connector_caller.h"
#include <QTimer>
#include <QMessageBox>

#include "../net_connector/net_connector_global.h"
#include "../net_connector/public/protocol/internet_protocol_packet.h"

#if defined(_MSC_VER) && (_MSC_VER >= 1600)		
# pragma execution_character_set("utf-8")
#endif

static NetConnectorWifiInitFunc NetWifiInit;
static NetConnectorWifiDeInitFunc NetWifiDeInit;
static NetConnectorEthernetInitFunc NetEthernetInit;
static NetConnectorEthernetDeInitFunc NetEthernetDeInit;
static NetConnectorNetConnectFunc NetConnect;
static NetConnectorNetDisconnectFunc NetDisconnect;
static NetConnectorSetNetEventCallBackFunc NetSetNetEventCallBack;


void __stdcall NetEventCallBack(int event_type, const char* content, void* user_data) {
  NetConnectorCaller* caller = static_cast<NetConnectorCaller*>(user_data);
  if (!caller) {
    return;
  }
  caller->OnNetEventCallBack(event_type, content);
}


NetConnectorCaller::NetConnectorCaller(QWidget *parent)
  : QWidget(parent)
  , internet_dll_(nullptr)
  , is_wireless_(false) {
  ui.setupUi(this);
  QTimer::singleShot(0, [=]() {
    if (!Init()) {
      QMessageBox::information(this, "error", "Init error!");
    };
    });
  connect(this, &NetConnectorCaller::ShowResultMsg, this, &NetConnectorCaller::OnShowResultMsg);
}

NetConnectorCaller::~NetConnectorCaller() {
  if (internet_dll_) {
    NetWifiDeInit();
    FreeLibrary(internet_dll_);
  }
}

bool NetConnectorCaller::Init() {
  if (!InitDll()) {
    return false;
  }
  NetSetNetEventCallBack(NetEventCallBack, this);

  InitNet();
  return true;
}

bool NetConnectorCaller::InitDll() {
  if (internet_dll_) {
    return true;
  }
  internet_dll_ = LoadLibrary("net_connector.dll");
  if (!internet_dll_) {
    QMessageBox::information(this, "error", "net_connector.dll Not found");
    return false;
  }

  NetWifiInit = (NetConnectorWifiInitFunc)GetProcAddress(internet_dll_, "NetConnectorWifiInit");
  NetWifiDeInit = (NetConnectorWifiDeInitFunc)GetProcAddress(internet_dll_, "NetConnectorWifiDeInit");
  NetEthernetInit = (NetConnectorWifiInitFunc)GetProcAddress(internet_dll_, "NetConnectorEthernetInit");
  NetEthernetDeInit = (NetConnectorWifiDeInitFunc)GetProcAddress(internet_dll_, "NetConnectorWifiDeInit");
  NetConnect = (NetConnectorNetConnectFunc)GetProcAddress(internet_dll_, "NetConnectorNetConnect");
  NetDisconnect = (NetConnectorNetDisconnectFunc)GetProcAddress(internet_dll_, "NetConnectorNetDisconnect");
  NetSetNetEventCallBack = (NetConnectorSetNetEventCallBackFunc)GetProcAddress(internet_dll_, "NetConnectorSetNetEventCallBack");
  if (!NetWifiInit || !NetWifiDeInit || !NetConnect || !NetDisconnect || !NetSetNetEventCallBack
    || !NetEthernetInit || !NetEthernetDeInit) {
    QMessageBox::information(this, "error", "net_connector.dll error");
    FreeLibrary(internet_dll_);
    internet_dll_ = nullptr;
    return false;
  }
  return true;
}

void NetConnectorCaller::OnNetEventCallBack(int event_type, const char* content) {
  QString  utf8_str = QString::fromLocal8Bit(content);
  switch ((EventType)event_type)
  {
  case EVENT_WIFI_SCAN_COMPLETE:
    return OnWifiScanResult(content);
  case EVENT_ETH_LIST_ACHIEVE:
    return OnEthernetScanResult(content);
  case EVENT_WIFI_CONNECTION_COMPLETE:
    emit ShowResultMsg(utf8_str);
    return;
  case EVENT_WIFI_DISCONNECTED:
    emit ShowResultMsg(utf8_str);
    return;
  case EVENT_ETH_CONNECTION_COMPLETE:
    emit ShowResultMsg(utf8_str);
    return;
  case EVENT_ETH_CONNECTION_FAIL:
  case EVENT_ETH_CONNECTION_TIMEOUT:
    emit ShowResultMsg(utf8_str);
    return;
  case EVENT_ETH_LOGOFF_SUCCESS:
    emit ShowResultMsg(utf8_str);
    return;
  case EVENT_ETH_LOGOFF_TIMEOUT:
    emit ShowResultMsg(utf8_str);
    return;
  default:
    break;
  }
  return;
}
void NetConnectorCaller::OnWifiScanResult(const char* content) {
  InternetConnect::WifiSsidListResponse response;
  InternetConnect::InternetProtocolPacket::DecodeWifiListMsg(content, response);
  QTimer::singleShot(0, this, [=]() {OnAddDescriptionItems(response.ssid_list, response.connected_wifi); });
}

void NetConnectorCaller::OnEthernetScanResult(const char* content) {
  InternetConnect::NetCardListResponse response;
  InternetConnect::InternetProtocolPacket::DecodeNetCardListMsg(content, response);
  QTimer::singleShot(0, this, [=]() {OnAddDescriptionItems(response.net_card_list, ""); });
}

std::string NetConnectorCaller::GetSelectedSsid() {
  std::string text = ui.comboBox_des->currentText().toStdString();
  std::string code = "(已连接)";
  int pos = text.find(code);
  if (pos != -1) {
    text = text.substr(0, pos);
  }
  return text;
}

void NetConnectorCaller::InitNet() {
  ui.comboBox_des->clear();
  if (is_wireless_) {
    ui.pushButton_switch->setText(tr("切换有线"));
    ui.label_des->setText(tr("WLAN: "));
    ui.label_scan->setText(tr("扫描中 ..."));
    ui.label_scan->show();
    NetWifiInit();
  }
  else {
    ui.pushButton_switch->setText(tr("切换无线"));
    ui.label_des->setText(tr("有线: "));
    ui.label_scan->hide();
    NetEthernetInit();
  }
}

void NetConnectorCaller::OnAddDescriptionItems(const std::set<std::string>& list, const std::string& connected) {
  QString selected = ui.comboBox_des->currentText();
  ui.comboBox_des->clear();
  for (auto item : list) {
    QString item_text = (item.c_str());
    if (!connected.empty() && connected == item) {
      item_text = QString("%1(已连接)").arg(item_text);
    }
    ui.comboBox_des->addItem(item_text);
  }

  if (ui.comboBox_des->count() <= 1) {
    ui.comboBox_des->setEnabled(false);
  }
  else {
    ui.comboBox_des->setEnabled(true);
    if (!selected.isNull() && !selected.isEmpty()) {
      ui.comboBox_des->setCurrentText(selected);
      ui.label_scan->clear();
    }
  }
}

void NetConnectorCaller::on_pushButton_connect_clicked() {
  NetConnect(GetSelectedSsid().c_str(), ui.lineEdit_username->text().toStdString().c_str()
    , ui.lineEdit_password->text().toStdString().c_str());
}

void NetConnectorCaller::on_pushButton_disconnect_clicked() {
  NetDisconnect(GetSelectedSsid().c_str());
}

void NetConnectorCaller::on_pushButton_switch_clicked() {
  is_wireless_ = !is_wireless_;
  InitNet();
}

void NetConnectorCaller::OnShowResultMsg(const QString& result) {
  QMessageBox::information(this, "Info", result);
}