#include "chap_ms.h"

#include <openssl/rand.h>
#include <iostream>

#include "ppp-crypto.h"
#include "pppcrypt.h"
#include "func_util.h"

/* E=eeeeeeeeee error codes for MS-CHAP failure messages. */
#define MS_CHAP_ERROR_RESTRICTED_LOGON_HOURS	646
#define MS_CHAP_ERROR_ACCT_DISABLED		647
#define MS_CHAP_ERROR_PASSWD_EXPIRED		648
#define MS_CHAP_ERROR_NO_DIALIN_PERMISSION	649
#define MS_CHAP_ERROR_AUTHENTICATION_FAILURE	691
#define MS_CHAP_ERROR_CHANGING_PASSWORD		709

#define MAX_NT_PASSWORD		256	/* Max (Unicode) chars in an NT pass */

#define MS_CHAP2_PEER_CHAL_LEN	16

#define CHAPMS2_MAX_RESPONSE_CACHE_SIZE 10
struct chapms2_response_cache_entry
  chapms2_response_cache[CHAPMS2_MAX_RESPONSE_CACHE_SIZE];
int chapms2_response_cache_next_index = 0;
int chapms2_response_cache_size = 0;

ChapMs::ChapMs()
{
}


ChapMs::~ChapMs()
{
}

void ChapMs::generate_challenge(unsigned char *challenge) {
  *challenge++ = 16;

  RAND_bytes(challenge, 16);
}

int ChapMs::verify_response(int id, char *name,
  unsigned char *secret, int secret_len,
  unsigned char *challenge, unsigned char *response,
  char *message, int message_space) {
  unsigned char md[MS_CHAP2_RESPONSE_LEN];
  char saresponse[MS_AUTH_RESPONSE_LENGTH + 1];
  int challenge_len, response_len;

  challenge_len = *challenge++;	/* skip length, is 16 */
  response_len = *response++;
  if (response_len != MS_CHAP2_RESPONSE_LEN)
    goto bad;	/* not even the right length */

              /* Generate the expected response and our mutual auth. */
  ChapMS2(challenge, &response[MS_CHAP2_PEER_CHALLENGE], name,
    (char *)secret, secret_len, md,
    (unsigned char *)saresponse, MS_CHAP2_AUTHENTICATOR);

  if (memcmp(&md[MS_CHAP2_NTRESP], &response[MS_CHAP2_NTRESP],
    MS_CHAP2_NTRESP_LEN) == 0) {
    if (response[MS_CHAP2_FLAGS])
      sprintf_s(message, message_space, "S=%s", saresponse);
    else
      sprintf_s(message, message_space, "S=%s M=%s",
        saresponse, "Access granted");
    return 1;
  }

bad:
//   sprintf_s(message, message_space, "E=691 R=1 C=%0.*B V=0 M=%s",
//     challenge_len, challenge, "Access denied");
  sprintf_s(message, message_space, "E=691 R=1 C=%s V=0 M=%s",
    challenge, "Access denied");
  return 0;

}

void ChapMs::make_response(unsigned char *response, int id, const char *our_name,
  const unsigned char *challenge, const char *secret, int secret_len,
  unsigned char *priv) {
  const struct chapms2_response_cache_entry *cache_entry;
  unsigned char auth_response[MS_AUTH_RESPONSE_LENGTH + 1];

  challenge++;	/* skip length, should be 16 */
  *response++ = MS_CHAP2_RESPONSE_LEN;
  cache_entry = chapms2_find_in_response_cache(id, challenge, NULL);
  if (cache_entry) {
    memcpy(response, cache_entry->response, MS_CHAP2_RESPONSE_LEN);
    return;
  }
  ChapMS2(challenge,nullptr, 
    our_name, secret, secret_len, response, auth_response,
    MS_CHAP2_AUTHENTICATEE);
  chapms2_add_to_response_cache(id, challenge, response, auth_response);
}

int ChapMs::check_success(int id, const unsigned char *msg, int len) {
  if ((len < MS_AUTH_RESPONSE_LENGTH + 2) ||
    strncmp((char *)msg, "S=", 2) != 0) {
    /* Packet does not start with "S=" */
    //error("MS-CHAPv2 Success packet is badly formed.");
    return 0;
  }
  msg += 2;
  len -= 2;
  if (len < MS_AUTH_RESPONSE_LENGTH
    || !chapms2_find_in_response_cache(id, NULL /* challenge */, msg)) {
    /* Authenticator Response did not match expected. */
    //error("MS-CHAPv2 mutual authentication failed.");
    return 0;
  }
  /* Authenticator Response matches. */
  msg += MS_AUTH_RESPONSE_LENGTH; /* Eat it */
  len -= MS_AUTH_RESPONSE_LENGTH;
  if ((len >= 3) && !strncmp((char *)msg, " M=", 3)) {
    //msg += 3; /* Eat the delimiter */
  }
  else 	if ((len >= 2) && !strncmp((char *)msg, "M=", 2)) {
    //msg += 2; /* Eat the delimiter */
  }
  else if (len) {
    /* Packet has extra text which does not begin " M=" */
    //error("MS-CHAPv2 Success packet is badly formed.");
    return 0;
  }
  return 1;
}

void ChapMs::handle_failure(const unsigned char *inp, int len) {
  int err;
  const char* p;
  char* msg;

  /* We want a null-terminated string for strxxx(). */
  msg = (char*)malloc(size_t(len) + 1);
  if (!msg) {
    //notice("Out of memory in chapms_handle_failure");
    return;
  }
  BCOPY(inp, msg, len);
  msg[len] = 0;
  p = msg;

  if (!strncmp(p, "E=", 2))
    err = strtol(p + 2, NULL, 10); /* Remember the error code. */
  else
    goto print_msg; /* Message is badly formatted. */

  if (len && ((p = strstr(p, " M=")) != NULL)) {
    /* M=<message> field found. */
    p += 3;
  }
  else {
    /* No M=<message>; use the error code. */
    switch (err) {
    case MS_CHAP_ERROR_RESTRICTED_LOGON_HOURS:
      p = "E=646 Restricted logon hours";
      break;

    case MS_CHAP_ERROR_ACCT_DISABLED:
      p = "E=647 Account disabled";
      break;

    case MS_CHAP_ERROR_PASSWD_EXPIRED:
      p = "E=648 Password expired";
      break;

    case MS_CHAP_ERROR_NO_DIALIN_PERMISSION:
      p = "E=649 No dialin permission";
      break;

    case MS_CHAP_ERROR_AUTHENTICATION_FAILURE:
      p = "E=691 Authentication failure";
      break;

    case MS_CHAP_ERROR_CHANGING_PASSWORD:
      /* Should never see this, we don't support Change Password. */
      p = "E=709 Error changing password";
      break;

    default:
      free(msg);
      //error("Unknown MS-CHAP authentication failure: %.*v",
      //len, inp);
      return;
    }
  }
print_msg:
  if (p != NULL)
    //error("MS-CHAP authentication failed: %v", p);
    free(msg);
}

void ChapMs::ChallengeHash(u_char PeerChallenge[16], const u_char *rchallenge,
  const char *username, u_char Challenge[8]) {
  PPP_MD_CTX* ctx;
  unsigned int     hash_len;
  const char	*user;

  /* remove domain from "domain\username" */
  if ((user = strrchr(username, '\\')) != NULL)
    ++user;
  else
    user = username;

  ctx = PPP_MD_CTX_new();
  if (ctx != NULL) {

    if (PPP_DigestInit(ctx, PPP_sha1())) {

      if (PPP_DigestUpdate(ctx, PeerChallenge, 16)) {

        if (PPP_DigestUpdate(ctx, rchallenge, 16)) {

          if (PPP_DigestUpdate(ctx, user, strlen(user))) {

            hash_len = SHA_DIGEST_LENGTH;
            u_char	hash[SHA_DIGEST_LENGTH];
            if (PPP_DigestFinal(ctx, hash, &hash_len)) {

              BCOPY(hash, Challenge, 8);
            }
          }
        }
      }
    }

    PPP_MD_CTX_free(ctx);
  }
}

void ChapMs::NTPasswordHash(u_char *secret, int secret_len, unsigned char* hash) {
  PPP_MD_CTX* ctx = PPP_MD_CTX_new();
  if (ctx != NULL) {

    if (PPP_DigestInit(ctx, PPP_md4())) {

      if (PPP_DigestUpdate(ctx, secret, secret_len)) {

        unsigned int hash_len = MD4_DIGEST_LENGTH;
        PPP_DigestFinal(ctx, hash, &hash_len);
      }
    }

    PPP_MD_CTX_free(ctx);
  }
}

void ChapMs::ChapMS2_NT(const u_char *rchallenge, u_char PeerChallenge[16], const char *username,
  const char *secret, int secret_len, u_char NTResponse[24]) {
  u_char	unicodePassword[MAX_NT_PASSWORD * 2];
  u_char	PasswordHash[MD4_DIGEST_LENGTH];
  u_char	Challenge[8];

  ChallengeHash(PeerChallenge, rchallenge, username, Challenge);

  /* Hash the Unicode version of the secret (== password). */
  FuncUtil::ascii2unicode(secret, secret_len, unicodePassword);
  NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);

  ChallengeResponse(Challenge, PasswordHash, NTResponse);
}

void ChapMs::GenerateAuthenticatorResponse(unsigned char* PasswordHashHash,
  unsigned char *NTResponse, unsigned char *PeerChallenge,
  const unsigned char *rchallenge, const char *username,
  unsigned char *authResponse) {
  PPP_MD_CTX *ctx;
  u_char	Digest[SHA_DIGEST_LENGTH] = { 0 };
  unsigned int     hash_len;
  u_char	Challenge[8];

  ctx = PPP_MD_CTX_new();
  if (ctx != NULL) {

    if (PPP_DigestInit(ctx, PPP_sha1())) {

      if (PPP_DigestUpdate(ctx, PasswordHashHash, MD4_DIGEST_LENGTH)) {

        if (PPP_DigestUpdate(ctx, NTResponse, 24)) {
          u_char Magic1[39] = /* "Magic server to client signing constant" */
          { 0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
            0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
            0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
            0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74 };
          if (PPP_DigestUpdate(ctx, Magic1, sizeof(Magic1))) {

            hash_len = sizeof(Digest);
            PPP_DigestFinal(ctx, Digest, &hash_len);
          }
        }
      }
    }
    PPP_MD_CTX_free(ctx);
  }

  ChallengeHash(PeerChallenge, rchallenge, username, Challenge);

  ctx = PPP_MD_CTX_new();
  if (ctx != NULL) {

    if (PPP_DigestInit(ctx, PPP_sha1())) {

      if (PPP_DigestUpdate(ctx, Digest, sizeof(Digest))) {

        if (PPP_DigestUpdate(ctx, Challenge, sizeof(Challenge))) {
          u_char Magic2[41] = /* "Pad to make it do more than one iteration" */
          { 0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
            0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
            0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
            0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
            0x6E };
          if (PPP_DigestUpdate(ctx, Magic2, sizeof(Magic2))) {

            hash_len = sizeof(Digest);
            PPP_DigestFinal(ctx, Digest, &hash_len);
          }
        }
      }
    }

    PPP_MD_CTX_free(ctx);
  }

  /* Convert to ASCII hex string. */
  for (int i = 0; i < sizeof(Digest); i++) {//MAX((MS_AUTH_RESPONSE_LENGTH / 2), sizeof(Digest))
    sprintf_s((char *)&authResponse[i * 2], (41 - size_t(i) * 2), "%02X", Digest[i]);
  }
}

void ChapMs::GenerateAuthenticatorResponsePlain
(const char *secret, int secret_len,
  u_char NTResponse[24], u_char PeerChallenge[16],
  const u_char *rchallenge, const char *username,
  u_char authResponse[41]) {
  u_char	unicodePassword[MAX_NT_PASSWORD * 2];
  u_char	PasswordHash[MD4_DIGEST_LENGTH];
  u_char	PasswordHashHash[MD4_DIGEST_LENGTH];

  /* Hash (x2) the Unicode version of the secret (== password). */
  FuncUtil::ascii2unicode(secret, secret_len, unicodePassword);
  NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);
  NTPasswordHash(PasswordHash, sizeof(PasswordHash),
    PasswordHashHash);

  GenerateAuthenticatorResponse(PasswordHashHash, NTResponse, PeerChallenge,
    rchallenge, username, authResponse);
}

void ChapMs::ChapMS2(const u_char *rchallenge, u_char *PeerChallenge,
  const char *user, const char *secret, int secret_len, u_char *response,
  u_char authResponse[41], int authenticator) {
  u_char *p = &response[MS_CHAP2_PEER_CHALLENGE];

  BZERO(response, MS_CHAP2_RESPONSE_LEN);

  /* Generate the Peer-Challenge if requested, or copy it if supplied. */
  if (!PeerChallenge)
    for (int i = 0; i < MS_CHAP2_PEER_CHAL_LEN; i++) {
      *p++ = (u_char)(FuncUtil::drand48() * 0xff);
    }
  else
    BCOPY(PeerChallenge, &response[MS_CHAP2_PEER_CHALLENGE],
      MS_CHAP2_PEER_CHAL_LEN);

  /* Generate the NT-Response */
  ChapMS2_NT(rchallenge, &response[MS_CHAP2_PEER_CHALLENGE], user,
    secret, secret_len, &response[MS_CHAP2_NTRESP]);

  /* Generate the Authenticator Response. */
  GenerateAuthenticatorResponsePlain(secret, secret_len,
    &response[MS_CHAP2_NTRESP],
    &response[MS_CHAP2_PEER_CHALLENGE],
    rchallenge, user, authResponse);
}

struct chapms2_response_cache_entry* ChapMs::chapms2_find_in_response_cache(int id,
  const unsigned char *challenge, const unsigned char *auth_response) {
  int i;

  for (i = 0; i < chapms2_response_cache_size; i++) {
    if (id == chapms2_response_cache[i].id
      && (!challenge
        || memcmp(challenge,
          chapms2_response_cache[i].challenge,
          16) == 0)
      && (!auth_response
        || memcmp(auth_response,
          chapms2_response_cache[i].auth_response,
          MS_AUTH_RESPONSE_LENGTH) == 0)) {
      //dbglog("response found in cache (entry %d)", i);
      return &chapms2_response_cache[i];
    }
  }
  return NULL;  /* not found */
}

void ChapMs::chapms2_add_to_response_cache(int id, const unsigned char *challenge,
  unsigned char *response, unsigned char *auth_response) {
  int i = chapms2_response_cache_next_index;

  chapms2_response_cache[i].id = id;
  memcpy(chapms2_response_cache[i].challenge, challenge, 16);
  memcpy(chapms2_response_cache[i].response, response,
    MS_CHAP2_RESPONSE_LEN);
  memcpy(chapms2_response_cache[i].auth_response,
    auth_response, MS_AUTH_RESPONSE_LENGTH);
  chapms2_response_cache_next_index =
    (i + 1) % CHAPMS2_MAX_RESPONSE_CACHE_SIZE;
  if (chapms2_response_cache_next_index > chapms2_response_cache_size)
    chapms2_response_cache_size = chapms2_response_cache_next_index;
}

int ChapMs::ChallengeResponse(u_char *challenge,
  u_char *PasswordHash,
  u_char *response)
{
  u_char ZPasswordHash[21];

  BZERO(ZPasswordHash, sizeof(ZPasswordHash));
  BCOPY(PasswordHash, ZPasswordHash, MD4_DIGEST_LENGTH);

  if (PppCrypt::DesEncrypt(challenge, ZPasswordHash + 0, response + 0) &&
    PppCrypt::DesEncrypt(challenge, ZPasswordHash + 7, response + 8) &&
    PppCrypt::DesEncrypt(challenge, ZPasswordHash + 14, response + 16)) {
    return 1;
  }

  return 0;
}