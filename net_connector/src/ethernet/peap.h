#pragma once
#include "global.h"
#include "tls.h"
#include "chap_ms.h"

#include <string>

struct PeapPara {
  Tls* tls;

  u_char *in_buf;
  u_char *out_buf;
  int written;
  int read;
  int phase;

  u_char tk[PEAP_TLV_TK_LEN];
  u_char ipmk[PEAP_TLV_IPMK_LEN];
  u_char nonce[PEAP_TLV_NONCE_LEN];
  ChapMs chap;
};

enum PeapFlag {
  PEAP_S_FLAG_SET = 0x20,
  PEAP_L_FLAG_SET = 0x80,
  PEAP_LM_FLAG_SET = 0xC0,
  PEAP_M_FLAG_SET = 0x40,
  PEAP_NO_FLAGS = 0x00,
};

enum ChapOpCode {
  CHAP_CHALLENGE = 1,
  CHAP_RESPONSE = 2,
  CHAP_SUCCESS = 3,
  CHAP_FAILURE = 4,
};

class Peap {
public:
  Peap();
  ~Peap();

  void setUserInfo(const std::string& username, const std::string& password) {
    username_ = username;
    password_ = password;
  }
  int Init();
  void clear();
  int handlePeapData(const u_char* request, int len,
    const u_char& id, u_char* resp, int out_len);

private:
  int ack(u_char* out);
  int response(const u_char* buf, int len, u_char* out);
  int doInnerEap(const u_char* buf, int len, u_char* out);
  int responseIdentity(const u_char* buf, int len, u_char* out);
  int responseEapTls(u_char* out);
  int responseMsChapV2(const u_char* buf, int len, u_char* out);
  int responseChapChallenge(const u_char* buf, int len, u_char* out);
  int responseChapSuccess(const u_char* buf, int len, u_char cache_chap_id, u_char* out);
  int responseChapFailure(const u_char* buf, int len, u_char* out);

  void verifyCompoundMac(const u_char *in_buf);
  void generateCmk(u_char *nonce, u_char *tlv_response_out, int client);
  void prfplus(const u_char *seed, size_t seed_len, u_char *key, size_t key_len, u_char *out_buf, size_t pfr_len);

private:
  std::string username_;
  std::string password_;

  PeapPara peap_para_;
  u_char peap_id_;
};

