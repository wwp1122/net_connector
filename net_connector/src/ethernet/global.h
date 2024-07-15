#pragma once

typedef unsigned char u_char;


#define EAP_HEADER_LENTH 4
#define PEAP_FLAG_LENGTH 1
#define	PEAP_TLV_TK_LEN			60
#define PEAP_TLV_HEADERLEN		8
#define PEAP_TLV_RESULT_LEN		7
#define PEAP_TLV_LEN			71

#define	PEAP_TLV_IPMK_LEN		40
#define	PEAP_TLV_NONCE_LEN		32

#define MS_CHAP2_RESPONSE_LEN	49	/* Response length for MS-CHAPv2 */
#define MS_AUTH_RESPONSE_LENGTH	40	/* MS-CHAPv2 authenticator response, */

#define MS_CHAP2_NTRESP_LEN	24

//define type

#define PEAP_TLV_TYPE			12

#define MS_CHAP2_PEER_CHALLENGE	0

#define MS_CHAP2_AUTHENTICATEE 0
#define MS_CHAP2_AUTHENTICATOR 1
#define MS_CHAP2_NTRESP		24
#define MS_CHAP2_FLAGS		48


//define function
#define BCOPY(s, d, l)		memcpy(d, s, l)
#define BZERO(s, n)		memset(s, 0, n)
#define	BCMP(s1, s2, l)		memcmp(s1, s2, l)

#define GETCHAR(c, cp) { \
	(c) = *(cp)++; \
}
#define PUTCHAR(c, cp) { \
	*(cp)++ = (u_char) (c); \
}


#define GETSHORT(s, cp) { \
	(s) = *(cp)++ << 8; \
	(s) |= *(cp)++; \
}
#define PUTSHORT(s, cp) { \
	*(cp)++ = (u_char) ((s) >> 8); \
	*(cp)++ = (u_char) (s); \
}

#define GETLONG(l, cp) { \
	(l) = *(cp)++ << 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; \
}
#define PUTLONG(l, cp) { \
	*(cp)++ = (u_char) ((l) >> 24); \
	*(cp)++ = (u_char) ((l) >> 16); \
	*(cp)++ = (u_char) ((l) >> 8); \
	*(cp)++ = (u_char) (l); \
}

#ifndef MIN
#define MIN(a, b)	((a) < (b)? (a): (b))
#endif
#ifndef MAX
#define MAX(a, b)	((a) > (b)? (a): (b))
#endif





enum EAPCode {
  EAP_REQUEST = 1,
  EAP_RESPONSE = 2,
  EAP_SUCCESS = 3,
  EAP_FAILURE = 4,
};

enum EAPType {
  EAPT_IDENTITY = 1,
  EAPT_NOTIFICATION = 2,
  EAPT_NAK = 3,
  EAPT_MD5CHAP = 4,
  EAPT_TLS = 13,
  EAPT_AVAILABLE = 20,
  EAPT_PEAP = 25,
  EAPT_MSCHAPV2 = 26,
};