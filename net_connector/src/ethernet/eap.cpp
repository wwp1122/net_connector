#include "eap.h"

#include <atomic>
#include <windows.h>
#include "../../net_connector_define.h"

const u_char c_broadcast_addr[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };  // 广播MAC地址
const u_char c_multcast_addr[6] = { 0x01,0x80,0xc2,0x00,0x00,0x03 };  // 多播MAC地址

#define AUTH_HEADER_LENTH 18

std::atomic<bool> connection_stop = false;

void ProcessRecvData(EapProcess* eap) {
  if (!eap) {
    return;
  }

  pcap_t* adapter = eap->GetAdapterHander();
  if (!adapter) {
    return;
  }

  struct pcap_pkthdr *header;
  const unsigned char	*captured;
  while (true) {
    if (connection_stop) {
      return;
    }

    int ret = pcap_next_ex(adapter, &header, &captured);
    if (1 == ret) {
      eap->HandleRecvData(captured);
    }
    else {
      Sleep(20);
    }
  }
}

Eap::Eap()
  :adapter_hander_(nullptr)
  , recv_thread(nullptr)
  , result_callback_(nullptr) {
  stop_timer_.setSingleShot(true);
  //QTimer & Qt connect
  QObject::connect(&stop_timer_, &QTimer::timeout, this, &Eap::OnTimerStop);
  QObject::connect(this, &Eap::StopThread, this, &Eap::Clear, Qt::QueuedConnection);
}


Eap::~Eap() {
  Clear();
}

void Eap::OnTimerStop() {
  if (!result_callback_) {
    Clear();
    return;
  }
  if (connect_info_.disconnect) {
    result_callback_(EVENT_ETH_LOGOFF_TIMEOUT, "以太网注销超时!");
  }
  else {
    result_callback_(EVENT_ETH_CONNECTION_TIMEOUT, "以太网连接超时!");
  }
  Clear();
}

void Eap::Clear() {
  connection_stop = true;
  if (recv_thread) {
    recv_thread->join();
    delete recv_thread;
    recv_thread = nullptr;
  }

  if (adapter_hander_) {
    pcap_close(adapter_hander_);
    adapter_hander_ = nullptr;
  }
}

bool Eap::Connect(const ConnectInfo& info) {
  connect_info_ = info;
  sprintf_s(connect_info_.network_card, sizeof(connect_info_.network_card), info.network_card);

  peap_.setUserInfo(connect_info_.username, connect_info_.password);
  peap_.Init();
  if (!Init()) {
    return false;
  }

  stop_timer_.start(10000);

  ResetThread();
  Start();
  return true;
}

bool Eap::Disconnect(const ConnectInfo& info) {
  connect_info_ = info;
  if (!Init()) {
    return false;
  }

  stop_timer_.start(2000);

  ResetThread();
  bool ret = (LogOff() == 0);
  return ret;
}

int Eap::HandleRecvData(const u_char* request) {
  if (0x00 != request[15]) {
    return 0;  // 可能收到来自组播的EAPOL-Start帧? request[15] = 0x01
  }
  EAPCode eap_code = static_cast<EAPCode>(request[18]);
  switch (eap_code) {
  case EAP_REQUEST:
    ResponseRequest(request);
    break;
  case EAP_SUCCESS:
    if (result_callback_) {
      result_callback_(EVENT_ETH_CONNECTION_COMPLETE, "以太网连接成功!");
    }
    stop_timer_.stop();
    break;
  case EAP_FAILURE:
    if (result_callback_) {
      if (connect_info_.disconnect) {
        result_callback_(EVENT_ETH_LOGOFF_SUCCESS, "以太网注销成功!");
      }
      else {
        uint8_t errtype = request[22];
        uint8_t msgsize = request[23];
        std::string msg = "以太网连接失败";
        if (errtype == 0x09 && msgsize > 0) {
          msg += ", error:";
          msg += (const char*)&request[24];
        }
        else if (errtype == 0x08) {
          msg += ":无流量，请重新连接";
        }
        result_callback_(EVENT_ETH_CONNECTION_FAIL, msg.c_str());
      }
    }
    stop_timer_.stop();
    emit StopThread();
    break;
  }
  return 0;
}

void Eap::SetResultCallBack(std::function<void(int result, const std::string& content)> resultCallBack) {
  result_callback_ = resultCallBack;
}

void Eap::ResetThread() {
  if (recv_thread) {
    Clear();
    Init();
  }
  connection_stop = false;
  recv_thread = new std::thread(ProcessRecvData, this);
}

bool Eap::Init() {
  if (!OpenLive()) {
    return false;
  }

  memcpy(eth_header_, c_multcast_addr, 6);
  memcpy(eth_header_ + 6, connect_info_.mac, 6);
  eth_header_[12] = 0x88;
  eth_header_[13] = 0x8e;// 802.1x Authentication(0x888e)
  return true;
}

std::string Eap::FindDevs(const std::string& name) {
  std::string pcap_name = name;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t* alldevs, * d;
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    return pcap_name;
  }

  for (d = alldevs; d != NULL; d = d->next) {
    std::string devs_name = d->name;
    if (devs_name.find(name) != std::string::npos) {
      pcap_name = devs_name;
      break;
    }
  }

  pcap_freealldevs(alldevs);
  return pcap_name;
}

bool Eap::OpenLive() {
  if (adapter_hander_) {
    return true;
  }

  char error[PCAP_ERRBUF_SIZE];
  const int default_timeout = 20;
  std::string pcap_name = FindDevs(connect_info_.network_card);
  adapter_hander_ = pcap_open_live(pcap_name.c_str(), 65536, 1, default_timeout, error);
  if (nullptr == adapter_hander_) {
    std::string err_str = "打开以太网卡失败! ";
    err_str += error;
    result_callback_(EVENT_ETH_CONNECTION_TIMEOUT, err_str);
    return false;
  }

  SetPcapHostFilter(connect_info_.mac, false);
  return true;
}

int Eap::Start() {
  u_char packet[AUTH_HEADER_LENTH];

  memcpy(packet, eth_header_, ETH_HEADER_LENGTH);
  packet[14] = 0x01;//version
  packet[15] = 0x01;//start
  packet[16] = packet[17] = 0x00;//length

  return pcap_sendpacket(adapter_hander_, packet, sizeof(packet));
}

int Eap::LogOff() {
  if (!adapter_hander_) {
      return 0;
  }
  u_char packet[AUTH_HEADER_LENTH];

  memcpy(packet, eth_header_, ETH_HEADER_LENGTH);
  packet[14] = 0x01;//version
  packet[15] = 0x02;//log off
  packet[16] = packet[17] = 0x00;//length

  return pcap_sendpacket(adapter_hander_, packet, sizeof(packet));
}

int Eap::ResponseRequest(const u_char* request) {
  EAPType eap_type = static_cast<EAPType>(request[22]);
  switch (eap_type)
  {
  case EAPT_IDENTITY:
    return ResponseIdentity(request);
  case EAPT_PEAP:
    return ResponsePeap(request);
  default:
    return ResponseLegacyNak(request[19]);
  }

  return 0;
}

int Eap::ResponseIdentity(const u_char* request) {
  u_char switch_mac[MAC_SIZE];
  for (int i = 0; i < MAC_SIZE; ++i) {
    switch_mac[i] = request[6 + i];
  }
  ChangeSwitchMac(switch_mac);

  u_char response[128];
  memcpy(response, eth_header_, ETH_HEADER_LENGTH);
  response[14] = 0x01;//version
  response[15] = 0x00;//eap packet
  response[18] = (EAPCode)EAP_RESPONSE;
  response[19] = request[19];

  response[22] = (EAPType)EAPT_IDENTITY;
  int name_len = connect_info_.username.length();
  int total_len = name_len + 23;
  if (total_len > 128) {
    return 1;
  }

  memcpy(response + 23, connect_info_.username.c_str(), name_len);
  unsigned short eap_len = htons(total_len - AUTH_HEADER_LENTH);
  memcpy(response + 16, &eap_len, sizeof(eap_len));
  memcpy(response + 20, &eap_len, sizeof(eap_len));
  return pcap_sendpacket(adapter_hander_, response, total_len);
}

int Eap::ResponseMd5(const u_char* request) {
  //TODO:
  return 0;
}

int Eap::ResponseLegacyNak(u_char eap_id) {
  u_char response[24];

  int total_len = 24;
  unsigned short eap_len = htons(total_len);

  memcpy(response, eth_header_, 14);
  response[14] = 0x1;
  response[15] = 0x0;
  memcpy(response + 16, &eap_len, sizeof(eap_len));
  response[18] = EAP_RESPONSE;
  response[19] = eap_id;
  memcpy(response + 20, &eap_len, sizeof(eap_len));
  response[22] = EAPT_NAK;
  response[23] = EAPT_PEAP; // Desired Auth Type: Protected EAP(EAP-PEAP)
  return pcap_sendpacket(adapter_hander_, response, total_len);
}

int Eap::ResponsePeap(const u_char* request) {
  int response_max_len = 2048;
  u_char response[2048] = { 0 };
  unsigned short request_eap_len;
  memcpy(&request_eap_len, &request[20], sizeof(request_eap_len));
  int request_peap_len = ntohs(request_eap_len) - EAP_HEADER_LENTH - PEAP_FLAG_LENGTH;
  int response_peap_len = peap_.handlePeapData(request + AUTH_HEADER_LENTH + EAP_HEADER_LENTH + PEAP_FLAG_LENGTH
    , request_peap_len, request[19], response + AUTH_HEADER_LENTH, response_max_len - AUTH_HEADER_LENTH);

  unsigned short data_len = htons(response_peap_len);
  memcpy(response, eth_header_, ETH_HEADER_LENGTH);
  response[14] = 0x01;
  response[15] = 0x00;
  memcpy(response + 16, &data_len, sizeof(data_len));
  return pcap_sendpacket(adapter_hander_, response, response_peap_len + AUTH_HEADER_LENTH);
}

void Eap::ChangeSwitchMac(u_char mac[MAC_SIZE]) {
  memcpy(eth_header_, mac, 6);
  SetPcapHostFilter(mac, true);
}

void Eap::SetPcapHostFilter(u_char mac[MAC_SIZE], bool src) {
  char filter[128];
  std::string src_dst = "dst";
  if (src) {
    src_dst = "src";
  }
  sprintf_s(filter, "(ether proto 0x888e) and (ether %s host %02x:%02x:%02x:%02x:%02x:%02x)",
    src_dst.c_str(), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  static std::string last_filter;
  if (last_filter == filter) {
    return;
  }
  last_filter = filter;

  struct bpf_program	fcode;
  pcap_compile(adapter_hander_, &fcode, filter, 1, 0xff);
  pcap_setfilter(adapter_hander_, &fcode);
}