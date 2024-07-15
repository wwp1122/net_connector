#pragma once
#include <openssl/x509.h>

#define	TLS_RECORD_MAX_SIZE		0x4000

struct TlsInfo {
  char* peer_name;
  bool client;
  X509* peer_cert;
};

class Tls
{
public:
  Tls();
  ~Tls();

  int Init();
  SSL* GetSsl() { return ssl_; }
  BIO* GetInBio() { return in_bio_; }
  BIO* GetOutBio() { return out_bio_; }

private:
  void SetOpts();
  bool SetVersion(int max_version);
  void SetVerify(int depth);
//   int SetVerifyInfo(const char *peer_name, const char *peer_cert,
//     bool client, struct TlsInfo **out);
//  void FreeVerifyInfo(struct TlsInfo **in);
  bool SetCa(const char* ca_dir, const char* ca_file);

private:
  SSL_CTX* ctx_;
  SSL* ssl_;
  BIO* in_bio_;
  BIO* out_bio_;
};

