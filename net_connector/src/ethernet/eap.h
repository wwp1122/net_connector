#pragma once

/*  eth header = 2 * mac(6) + eth type(2) = 14
**  eth type: 0x888e(802.1x Authentication), 0x0800(IPv4)...
**
**  802.1x header: version(1) + type(1) + eap length(2) = 4
**
**  eap header: code(1) + id(1) + eap length(2) = 4
**  eap type: MD5/PEAP/EAP-TLS(1)...
**
**  request packet = eth header(14) + 802.1x header(4) + eap header(4) + eap type(1) = 23
*/

#include <QObject>
#include <QTimer>
#include <pcap.h>
#include <thread>
#include <functional>

#include "peap.h"
#include "global.h"
#include "../util/net_card_util.h"

#define ETH_HEADER_LENGTH 14

struct ConnectInfo {
  ConnectInfo() {
    disconnect = false;
    memset(&mac, 0, sizeof(mac));
    memset(&network_card, 0, sizeof(network_card));
  }
  std::string username;
  std::string password;
  u_char mac[MAC_SIZE];
  char network_card[NET_CARD_NAME_MAX_LENGTH];
  bool disconnect;
};

class EapProcess {
public:
  virtual pcap_t* GetAdapterHander() = 0;
  virtual int HandleRecvData(const u_char* request) = 0;
};

class Eap :public QObject, public EapProcess {
  Q_OBJECT
public:
  Eap();
  ~Eap();

  bool Connect(const ConnectInfo& info);
  bool Disconnect(const ConnectInfo& info);

  int HandleRecvData(const u_char* request) override;
  pcap_t* GetAdapterHander() override { return adapter_hander_; }

  void SetResultCallBack(std::function<void(int result, const std::string& content)> resultCallBack);
private:
  void ResetThread();
  bool Init();
  std::string FindDevs(const std::string& name);
  bool OpenLive();
  int Start();
  int LogOff();
  int ResponseRequest(const u_char* request);
  int ResponseIdentity(const u_char* request);
  int ResponseMd5(const u_char* request);
  int ResponseLegacyNak(u_char eap_id);
  int ResponsePeap(const u_char* request);

  void ChangeSwitchMac(u_char mac[MAC_SIZE]);
  void SetPcapHostFilter(u_char mac[MAC_SIZE], bool src);

signals:
  void StopThread();
public slots :
  void OnTimerStop();
  void Clear();

private:
  std::thread* recv_thread;

  ConnectInfo connect_info_;
  u_char eth_header_[ETH_HEADER_LENGTH];
  std::function<void(int result, const std::string& content)> result_callback_;

  Peap peap_;

  QTimer stop_timer_;
  pcap_t* adapter_hander_;
};

