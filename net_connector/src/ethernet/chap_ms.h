#pragma once

#include "global.h"


struct chapms2_response_cache_entry {
  int id;
  unsigned char challenge[16];
  unsigned char response[MS_CHAP2_RESPONSE_LEN];
  unsigned char auth_response[MS_AUTH_RESPONSE_LENGTH];
};
class ChapMs
{
public:
  ChapMs();
  ~ChapMs();

  void generate_challenge(unsigned char *challenge);
  int verify_response(int id, char *name,
    unsigned char *secret, int secret_len,
    unsigned char *challenge, unsigned char *response,
    char *message, int message_space);
  void make_response(unsigned char *response, int id, const char *our_name,
    const unsigned char *challenge, const char *secret, int secret_len,
    unsigned char *priv);
  int check_success(int id, const unsigned char *pkt, int len);
  void handle_failure(const unsigned char *pkt, int len);

private:
  void ChallengeHash(u_char PeerChallenge[16], const u_char *rchallenge,
    const char *username, u_char Challenge[8]);
  void NTPasswordHash(u_char *secret, int secret_len, unsigned char* hash);
  void ChapMS2_NT(const u_char *rchallenge, u_char PeerChallenge[16], const char *username,
    const char *secret, int secret_len, u_char NTResponse[24]);
  void GenerateAuthenticatorResponse(unsigned char* PasswordHashHash,
      unsigned char *NTResponse, unsigned char *PeerChallenge,
    const unsigned char *rchallenge, const char *username,
      unsigned char *authResponse);
  void GenerateAuthenticatorResponsePlain
    (const char *secret, int secret_len,
      u_char NTResponse[24], u_char PeerChallenge[16],
      const u_char *rchallenge, const char *username,
      u_char authResponse[41]);
  void ChapMS2(const u_char *rchallenge, u_char *PeerChallenge,
    const char *user, const char *secret, int secret_len, u_char *response,
      u_char authResponse[41], int authenticator);
  struct chapms2_response_cache_entry* chapms2_find_in_response_cache(int id,
    const unsigned char *challenge, const unsigned char *auth_response);
  void chapms2_add_to_response_cache(int id, const unsigned char *challenge,
    unsigned char *response, unsigned char *auth_response);
  int ChallengeResponse(u_char *challenge,
    u_char *PasswordHash,
    u_char *response);
};

