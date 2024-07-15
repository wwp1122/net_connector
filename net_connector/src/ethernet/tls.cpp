#include "tls.h"

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <iostream>

#define TLS_VERIFY_NONE     "none"
#define TLS_VERIFY_NAME     "name"
#define TLS_VERIFY_SUBJECT  "subject"
#define TLS_VERIFY_SUFFIX   "suffix"

bool auth_required_ = false;
bool tls_verify_key_usage_ = false;
std::string tls_verify_method_ ;
int tls_verify_callback(int ok, X509_STORE_CTX *ctx)
{
  char subject[256];
  char cn_str[256];
  X509 *peer_cert;
  int err, depth;
  SSL *ssl;
  struct TlsInfo *inf;
  char *ptr1 = NULL, *ptr2 = NULL;

  peer_cert = X509_STORE_CTX_get_current_cert(ctx);
  err = X509_STORE_CTX_get_error(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);

  if (auth_required_ && !ok) {
    X509_NAME_oneline(X509_get_subject_name(peer_cert),
      subject, 256);

    X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert),
      NID_commonName, cn_str, 256);

    X509_verify_cert_error_string(err);
    return 0;
  }

  ssl = (SSL*)X509_STORE_CTX_get_ex_data(ctx,
    SSL_get_ex_data_X509_STORE_CTX_idx());

  inf = (struct TlsInfo*) SSL_get_ex_data(ssl, 0);
  if (inf == NULL) {
    return 0;
  }

  if (!depth)
  {
    /* Verify certificate based on certificate type and extended key usage */
    if (tls_verify_key_usage_) {
      int purpose = inf->client ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;
      if (X509_check_purpose(peer_cert, purpose, 0) == 0) {
        return 0;
      }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      int flags = inf->client ? XKU_SSL_SERVER : XKU_SSL_CLIENT;
      if (!(X509_get_extended_key_usage(peer_cert) & flags)) {
        return 0;
      }
#endif
    }

    /*
    * If acting as client and the name of the server wasn't specified
    * explicitely, we can't verify the server authenticity
    */
    if (tls_verify_method_.empty())
      tls_verify_method_ = TLS_VERIFY_NONE;

    if (!inf->peer_name || !strcmp(TLS_VERIFY_NONE, tls_verify_method_.c_str())) {
      return ok;
    }

    /* This is the peer certificate */
    X509_NAME_oneline(X509_get_subject_name(peer_cert),
      subject, 256);

    X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert),
      NID_commonName, cn_str, 256);

    /* Verify based on subject name */
    ptr1 = inf->peer_name;
    if (!strcmp(TLS_VERIFY_SUBJECT, tls_verify_method_.c_str())) {
      ptr2 = subject;
    }

    /* Verify based on common name (default) */
    if (strlen(tls_verify_method_.c_str()) == 0 ||
      !strcmp(TLS_VERIFY_NAME, tls_verify_method_.c_str())) {
      ptr2 = cn_str;
    }

    /* Match the suffix of common name */
    if (!strcmp(TLS_VERIFY_SUFFIX, tls_verify_method_.c_str())) {
      int len = strlen(ptr1);
      int off = strlen(cn_str) - len;
      ptr2 = cn_str;
      if (off > 0) {
        ptr2 = cn_str + off;
      }
    }

    if (strcmp(ptr1, ptr2)) {
      return 0;
    }

    if (inf->peer_cert) {
      if (X509_cmp(inf->peer_cert, peer_cert) != 0) {
        return 0;
      }
    }
  }

  return ok;
}

int X509_STORE_CTX_verify_callback(int ok, X509_STORE_CTX *) {
  return ok;
}

Tls::Tls()
  : ctx_(nullptr)
  , ssl_(nullptr)
  , out_bio_(nullptr)
  , in_bio_(nullptr) {
}


Tls::~Tls()
{
}

int Tls::Init() {
  if (ctx_ || ssl_) {
    return 0;
  }

  ctx_ = SSL_CTX_new(TLS_method());

  SSL_library_init();
  SSL_load_error_strings();
  SetOpts();
  SetVersion(TLS1_2_VERSION);
  SetVerify(5);
  SetCa("", "");

  out_bio_ = BIO_new(BIO_s_mem());
  in_bio_ = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(out_bio_, -1);
  BIO_set_mem_eof_return(in_bio_, -1);

  ssl_ = SSL_new(ctx_);
  SSL_set_bio(ssl_, in_bio_, out_bio_);
  SSL_set_connect_state(ssl_);

  return 0;
}

void Tls::SetOpts() {
  SSL_CTX_set_options(ctx_, /*SSL_OP_ALL | */SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
}

bool Tls::SetVersion(int max_version) {
  if (!SSL_CTX_set_max_proto_version(ctx_, max_version)) {
    return false;
  }

  return true;
}

void Tls::SetVerify(int depth) {
  //向上回溯次数(depth==1: 仅根证书通过验证)
  SSL_CTX_set_verify_depth(ctx_, depth);
  //SSL_VERIFY_NONE: 完全忽略验证证书的结果
  SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);// SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, tls_verify_callback);
  X509_STORE_CTX_set_verify_cb((X509_STORE_CTX *)ctx_, &X509_STORE_CTX_verify_callback);
}

/*
int Tls::SetVerifyInfo(const char *peer_name, const char *peer_cert,
  bool client, struct TlsInfo **out) {
  if (nullptr == out) {
    return -1;
  }

  struct TlsInfo *tmp = new TlsInfo;
  if (!tmp) {
    //fatal("Allocation error");
    return -1;
  }

  tmp->client = client;
  if (peer_name) {
    tmp->peer_name = _strdup(peer_name);
  }

  if (peer_cert && strlen(peer_cert) > 0) {
    FILE *fp;
    fopen_s(&fp, peer_cert, "r");
    if (fp) {
      tmp->peer_cert = PEM_read_X509(fp, NULL, NULL, NULL);
      fclose(fp);
    }

    if (!tmp->peer_cert) {
      //error("EAP-TLS: Error loading client certificate from file %s", peer_cert);
      FreeVerifyInfo(&tmp);
      return -1;
    }
  }

  SSL_set_ex_data(ssl_, 0, tmp);
  *out = tmp;
  return 0;
}

void Tls::FreeVerifyInfo(struct TlsInfo **in) {
  if (in && *in) {
    struct TlsInfo *tmp = *in;
    if (tmp->peer_name) {
      free(tmp->peer_name);
    }
    if (tmp->peer_cert) {
      X509_free(tmp->peer_cert);
    }
    free(tmp);
    *in = NULL;
  }
}*/

bool Tls::SetCa(const char* ca_dir, const char* ca_file) {
  if (ca_file && strlen(ca_file) == 0) {
    ca_file = NULL;
  }

  if (ca_dir && strlen(ca_dir) == 0) {
    ca_dir = NULL;
  }

  if (!SSL_CTX_load_verify_locations(ctx_, ca_file, ca_dir)) {

    if (ca_file) {
      //dbglog("CA certificate file = [%s]", ca_file);
    }

    if (ca_dir) {
      //dbglog("CA certificate path = [%s]", ca_dir);
    }

    return false;
  }

  return true;
}