#include "peap.h"

#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define	PEAP_PHASE_1 1
#define	PEAP_PHASE_2 2

#define	PEAP_HEADERLEN			6
#define	PEAP_FRAGMENT_LENGTH_FIELD	4
#define	PEAP_FLAGS_ACK			0

#define PEAP_CAPABILITIES_TYPE		254
#define PEAP_CAPABILITIES_LEN		12

#define	PEAP_TLV_TK_SEED_LABEL		"client EAP encryption"
#define	PEAP_TLV_IPMK_SEED_LABEL	"Inner Methods Compound Keys"

#define	PEAP_TLV_DATA_LEN		61
#define	PEAP_TLV_ISK_LEN		32
#define	PEAP_TLV_IPMKSEED_LEN		59
#define	PEAP_TLV_CMK_LEN		20
#define	PEAP_TLV_COMP_MAC_LEN		20

#define PEAP_TLV_LENGTH_FIELD		56

#define PEAP_TLV_SUBTYPE_REQUEST	0
#define PEAP_TLV_SUBTYPE_RESPONSE	1

#define	PEAP_TLV_TEMPKEY_LEN		40



#define MS_CHAP2_PEER_CHAL_LEN	16


Peap::Peap()
  :peap_id_(0) {
  peap_para_.tls = nullptr;
}

Peap::~Peap() {
  clear();
}

int Peap::Init() {
  peap_para_.in_buf = new u_char[TLS_RECORD_MAX_SIZE];;
  memset(peap_para_.in_buf, 0, TLS_RECORD_MAX_SIZE);
  peap_para_.out_buf = new u_char[TLS_RECORD_MAX_SIZE];;
  memset(peap_para_.out_buf, 0, TLS_RECORD_MAX_SIZE);

  peap_para_.phase = PEAP_PHASE_1;

  if (peap_para_.tls) {
    delete peap_para_.tls;
  }
  peap_para_.tls = new Tls;
  peap_para_.tls->Init();
  return 0;
}

void Peap::clear() {
  if (peap_para_.tls) {
    delete[] peap_para_.in_buf;
    delete[] peap_para_.out_buf;

    delete peap_para_.tls;
    peap_para_.tls = nullptr;
  }
}

int Peap::handlePeapData(const u_char* request, int len,
  const u_char& id, u_char* resp, int out_len) {
  peap_id_ = id;

  PeapFlag flag = static_cast<PeapFlag>(*request);
  ++request;
  --len;

  int ret;
  //std::string error;

  switch (flag) {
  case PEAP_S_FLAG_SET:
    ret = SSL_do_handshake(peap_para_.tls->GetSsl());
    if (1 != ret) {
      ret = SSL_get_error(peap_para_.tls->GetSsl(), ret);
      if (ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE) {
        //error = ERR_error_string(ret, NULL);
      }
    }
    peap_para_.read = BIO_read(peap_para_.tls->GetOutBio(), peap_para_.out_buf, TLS_RECORD_MAX_SIZE);
    return response(peap_para_.out_buf, peap_para_.read, resp);

  case PEAP_LM_FLAG_SET:
    request = request + PEAP_FRAGMENT_LENGTH_FIELD;
    peap_para_.written = BIO_write(peap_para_.tls->GetInBio(), request, len - PEAP_FRAGMENT_LENGTH_FIELD);
    return ack(resp);

  case PEAP_M_FLAG_SET:
    peap_para_.written = BIO_write(peap_para_.tls->GetInBio(), request, len);
    return ack(resp);

  case PEAP_L_FLAG_SET:
  case PEAP_NO_FLAGS:
    if (*request == PEAP_L_FLAG_SET) {
      request = request + PEAP_FRAGMENT_LENGTH_FIELD;
      peap_para_.written = BIO_write(peap_para_.tls->GetInBio(), request, len - PEAP_FRAGMENT_LENGTH_FIELD);
    }
    else {
      peap_para_.written = BIO_write(peap_para_.tls->GetInBio(), request, len);
    }

    if (peap_para_.phase == PEAP_PHASE_1) {
      ret = SSL_do_handshake(peap_para_.tls->GetSsl());
      if (ret != 1) {
        ret = SSL_get_error(peap_para_.tls->GetSsl(), ret);
        if (ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE) {
          //error = ERR_error_string(ret, NULL);
        }
      }
      if (SSL_is_init_finished(peap_para_.tls->GetSsl())) {
        peap_para_.phase = PEAP_PHASE_2;
      }
      if (BIO_ctrl_pending(peap_para_.tls->GetOutBio()) == 0) {
        return ack(resp);
      }
      peap_para_.read = 0;
      peap_para_.read = BIO_read(peap_para_.tls->GetOutBio(), peap_para_.out_buf,
        TLS_RECORD_MAX_SIZE);
      return response(peap_para_.out_buf, peap_para_.read, resp);
    }

    peap_para_.read = SSL_read(peap_para_.tls->GetSsl(), peap_para_.in_buf,
      TLS_RECORD_MAX_SIZE);
    //out_len = TLS_RECORD_MAX_SIZE;
    out_len = doInnerEap(peap_para_.in_buf, peap_para_.read, peap_para_.out_buf);
    if (out_len > 0) {
      peap_para_.written = SSL_write(peap_para_.tls->GetSsl(), peap_para_.out_buf, out_len);
      peap_para_.read = BIO_read(peap_para_.tls->GetOutBio(), peap_para_.out_buf,
        TLS_RECORD_MAX_SIZE);
      return response(peap_para_.out_buf, peap_para_.read, resp);
    }

  default:
    break;
  }

  return 0;
}


int Peap::ack(u_char* out) {
  PUTCHAR(EAP_RESPONSE, out);
  PUTCHAR(peap_id_, out);
  PUTSHORT(PEAP_HEADERLEN, out);
  PUTCHAR(EAPT_PEAP, out);
  PUTCHAR(PEAP_FLAGS_ACK, out);
  return PEAP_HEADERLEN;
}

int Peap::response(const u_char* buf, int len, u_char* out) {
  if (len <= 0) {
    return 0;
  }
  PUTCHAR(EAP_RESPONSE, out);
  PUTCHAR(peap_id_, out);

  int peap_len;
  if (PEAP_PHASE_1 == peap_para_.phase) {
    peap_len = PEAP_HEADERLEN + PEAP_FRAGMENT_LENGTH_FIELD + len;
  }
  else {
    peap_len = PEAP_HEADERLEN + len;
  }

  PUTSHORT(peap_len, out);
  PUTCHAR(EAPT_PEAP, out);

  if (PEAP_PHASE_1 == peap_para_.phase) {
    PUTCHAR(PEAP_L_FLAG_SET, out);
    PUTLONG(len, out);
  }
  else {
    PUTCHAR(PEAP_NO_FLAGS, out);
  }
  memcpy(out, buf, len);
  return peap_len;
}

int Peap::doInnerEap(const u_char* buf, int len, u_char* out) {
  int used = 0;
  if (*(buf + EAP_HEADER_LENTH) == PEAP_CAPABILITIES_TYPE &&
    len == (EAP_HEADER_LENTH + PEAP_CAPABILITIES_LEN)) {
    /* use original packet as template for response */
    BCOPY(buf, out, EAP_HEADER_LENTH + PEAP_CAPABILITIES_LEN);
    PUTCHAR(EAP_RESPONSE, out);
    PUTCHAR(peap_id_, out);
    /* change last byte to 0 to disable fragmentation */
    *(out + PEAP_CAPABILITIES_LEN + 1) = 0x00;
    used = EAP_HEADER_LENTH + PEAP_CAPABILITIES_LEN;
    return used;
  }

  SSL* ssl = peap_para_.tls->GetSsl();
  if (*(buf + EAP_HEADER_LENTH + PEAP_TLV_HEADERLEN) == PEAP_TLV_TYPE &&
    len == PEAP_TLV_LEN) {
    /* PEAP TLV message, do cryptobinding */
    SSL_export_keying_material(ssl, peap_para_.tk, PEAP_TLV_TK_LEN,
      PEAP_TLV_TK_SEED_LABEL, strlen(PEAP_TLV_TK_SEED_LABEL), NULL, 0, 0);
    /* verify server's CMK */
    verifyCompoundMac(buf + EAP_HEADER_LENTH + PEAP_TLV_RESULT_LEN + PEAP_TLV_HEADERLEN);
    /* generate client's CMK with new nonce */
    PUTCHAR(EAP_RESPONSE, out);
    PUTCHAR(peap_id_, out);
    PUTSHORT(PEAP_TLV_LEN, out);
    BCOPY(buf + EAP_HEADER_LENTH, out, PEAP_TLV_RESULT_LEN);
    out = out + PEAP_TLV_RESULT_LEN;
    RAND_bytes(peap_para_.nonce, PEAP_TLV_NONCE_LEN);
    generateCmk(peap_para_.nonce, out, 1);
    used = PEAP_TLV_LEN;
    return used;
  }

  int eap_type;
  GETCHAR(eap_type, buf);
  --len;

  switch (eap_type) {
  case EAPT_IDENTITY:
    return responseIdentity(buf, len, out);
  case EAPT_TLS:
    return responseEapTls(out);
  case EAPT_MSCHAPV2:
    return responseMsChapV2(buf, len, out);
  default:
    break;
  }
  return 0;
}

int Peap::responseIdentity(const u_char* buf, int len, u_char* out) {
  if (len >= 4 && buf[3] == 33) {
    PUTCHAR(2, out);
    BCOPY(buf, out, len);
    return len + 1;
  }
  /* Respond with our identity to the peer */
  PUTCHAR(EAPT_IDENTITY, out);
  BCOPY(username_.c_str(), out, username_.length());
  return (username_.length() + 1);
}

int Peap::responseEapTls(u_char* out) {
  PUTCHAR(EAPT_NAK, out);
  PUTCHAR(EAPT_MSCHAPV2, out);
  return 2;
}

int Peap::responseMsChapV2(const u_char* buf, int len, u_char* out) {
  if (len < 4) {
    return 0;
  }

  u_char op_code, chap_id;
  short ms_size;
  GETCHAR(op_code, buf);
  GETCHAR(chap_id, buf);
  GETSHORT(ms_size, buf);

  if (len != ms_size) {
    return 0;
  }

  len -= 4;
  ChapOpCode chap_op_code = static_cast<ChapOpCode>(op_code);
  switch (chap_op_code)
  {
  case CHAP_CHALLENGE:
    return responseChapChallenge(buf, len, out);
  case CHAP_SUCCESS:
    return responseChapSuccess(buf, len, chap_id, out);
  case CHAP_FAILURE:
    return responseChapFailure(out, len, out);
  default:
    PUTCHAR(EAPT_NAK, out);
    return 1;
  }
  return 0;
}

int Peap::responseChapChallenge(const u_char* in_buf, int in_len, u_char* outp) {
  const u_char *challenge = in_buf;	// VLEN + VALUE
  u_char vsize;

  GETCHAR(vsize, in_buf);
  in_len -= 1;

  if (vsize != MS_CHAP2_PEER_CHAL_LEN || in_len < MS_CHAP2_PEER_CHAL_LEN) {
    return 0;
  }

  //in_buf += MS_CHAP2_PEER_CHAL_LEN;
  //in_len -= MS_CHAP2_PEER_CHAL_LEN;

  u_char response[MS_CHAP2_RESPONSE_LEN + 1];

  peap_para_.chap.make_response(response, peap_id_, username_.c_str(),
    challenge, password_.c_str(), password_.length(), NULL);

  PUTCHAR(EAPT_MSCHAPV2, outp);
  PUTCHAR(CHAP_RESPONSE, outp);
  PUTCHAR(peap_id_, outp);
  PUTCHAR(0, outp);
  PUTCHAR(5 + username_.length() + MS_CHAP2_RESPONSE_LEN, outp);
  BCOPY(response, outp, MS_CHAP2_RESPONSE_LEN + 1);	// VLEN + VALUE
  outp += (MS_CHAP2_RESPONSE_LEN + 1);
  BCOPY(username_.c_str(), outp, username_.length());
  return (5 + username_.length() + MS_CHAP2_RESPONSE_LEN + 1);
}

int Peap::responseChapSuccess(const u_char* in_buf, int in_len, u_char cache_chap_id, u_char* outp) {
  u_char status = CHAP_FAILURE;
  if (peap_para_.chap.check_success(cache_chap_id, in_buf, in_len)) {
    //info("Chap authentication succeeded! %.*v", in_len, in_buf);
    status = CHAP_SUCCESS;
  }

  PUTCHAR(EAPT_MSCHAPV2, outp);
  PUTCHAR(status, outp);
  return 2;
}

int Peap::responseChapFailure(const u_char* in_buf, int in_len, u_char* outp) {
  u_char status = CHAP_FAILURE;
  peap_para_.chap.handle_failure(in_buf, in_len);
  PUTCHAR(EAPT_MSCHAPV2, outp);
  PUTCHAR(status, outp);
  return 2;
}

void Peap::verifyCompoundMac(const u_char *in_buf) {
  u_char nonce[PEAP_TLV_NONCE_LEN] = { 0 };
  u_char out_buf[PEAP_TLV_LEN] = { 0 };

  BCOPY(in_buf, nonce, PEAP_TLV_NONCE_LEN);
  generateCmk(nonce, out_buf, 0);
  if (memcmp((in_buf + PEAP_TLV_NONCE_LEN), (out_buf + PEAP_TLV_HEADERLEN + PEAP_TLV_NONCE_LEN), PEAP_TLV_CMK_LEN)) {
    //fatal("server's CMK does not match client's CMK, potential MiTM");
  }
}

void Peap::generateCmk(u_char *nonce, u_char *tlv_response_out, int client)
{
  const char *label = PEAP_TLV_IPMK_SEED_LABEL;
  u_char data_tlv[PEAP_TLV_DATA_LEN] = { 0 };
  u_char isk[PEAP_TLV_ISK_LEN] = { 0 };
  u_char ipmkseed[PEAP_TLV_IPMKSEED_LEN] = { 0 };
  u_char cmk[PEAP_TLV_CMK_LEN] = { 0 };
  u_char buf[PEAP_TLV_CMK_LEN + PEAP_TLV_IPMK_LEN] = { 0 };
  u_char compound_mac[PEAP_TLV_COMP_MAC_LEN] = { 0 };

  /* format outgoing CB TLV response packet */
  data_tlv[1] = PEAP_TLV_TYPE;
  data_tlv[3] = PEAP_TLV_LENGTH_FIELD;
  if (client)
    data_tlv[7] = PEAP_TLV_SUBTYPE_RESPONSE;
  else
    data_tlv[7] = PEAP_TLV_SUBTYPE_REQUEST;
  BCOPY(nonce, (data_tlv + PEAP_TLV_HEADERLEN), PEAP_TLV_NONCE_LEN);
  data_tlv[60] = EAPT_PEAP;


  BCOPY(label, ipmkseed, strlen(label));
  BCOPY(isk, ipmkseed + strlen(label), PEAP_TLV_ISK_LEN);
  prfplus(ipmkseed, PEAP_TLV_IPMKSEED_LEN,
    peap_para_.tk, PEAP_TLV_TEMPKEY_LEN, buf, PEAP_TLV_CMK_LEN + PEAP_TLV_IPMK_LEN);

  BCOPY(buf, peap_para_.ipmk, PEAP_TLV_IPMK_LEN);
  BCOPY(buf + PEAP_TLV_IPMK_LEN, cmk, PEAP_TLV_CMK_LEN);
  unsigned int len;
  if (!HMAC(EVP_sha1(), cmk, PEAP_TLV_CMK_LEN, data_tlv, PEAP_TLV_DATA_LEN, compound_mac, &len)) {
    //fatal("HMAC() failed");
  }
  BCOPY(compound_mac, data_tlv + PEAP_TLV_HEADERLEN + PEAP_TLV_NONCE_LEN, PEAP_TLV_COMP_MAC_LEN);
  /* do not copy last byte to response packet */
  BCOPY(data_tlv, tlv_response_out, PEAP_TLV_DATA_LEN - 1);
}

void Peap::prfplus(const u_char *seed, size_t seed_len, u_char *key, size_t key_len, u_char *out_buf, size_t pfr_len)
{
  u_char *buf, *hash;
  size_t max_iter;
  unsigned int len;

  max_iter = (pfr_len + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;
  buf = (u_char *)malloc(seed_len + max_iter * SHA_DIGEST_LENGTH);
  if (!buf) {
    //novm("pfr buffer");
    return;
  }
  hash = (u_char *)malloc(pfr_len + SHA_DIGEST_LENGTH);
  if (!hash) {
    //novm("hash buffer");
    free(buf);
    return;
  }

  for (size_t i = 0; i < max_iter; i++) {
    int pos;
    size_t j = 0;
    size_t k = 0;

    if (i > 0)
      j = SHA_DIGEST_LENGTH;
    for (k = 0; k < seed_len; k++)
      buf[j + k] = seed[k];
    pos = j + k;
    buf[pos] = i + 1;
    pos++;
    buf[pos] = 0x00;
    pos++;
    buf[pos] = 0x00;
    pos++;
    if (!HMAC(EVP_sha1(), key, key_len, buf, pos, (hash + i * SHA_DIGEST_LENGTH), &len)) {
      //fatal("HMAC() failed");
    }

    for (j = 0; j < SHA_DIGEST_LENGTH; j++)
      buf[j] = hash[i * SHA_DIGEST_LENGTH + j];
  }
  BCOPY(hash, out_buf, pfr_len);
  free(hash);
  free(buf);
}