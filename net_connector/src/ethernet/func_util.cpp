﻿#include "func_util.h"

#include <iostream>

void FuncUtil::ascii2unicode(const char ascii[], int ascii_len, u_char unicode[]) {
  int i;

  BZERO(unicode, ascii_len * 2);
  for (i = 0; i < ascii_len; i++)
    unicode[i * 2] = (u_char)ascii[i];
}

double FuncUtil::drand48() {
  return (double)rand() / (double)0x7fffffffL; /* 2**31-1 */
};