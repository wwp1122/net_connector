#pragma once
#include "global.h"
class FuncUtil
{
public:
  static void ascii2unicode(const char ascii[], int ascii_len, u_char unicode[]);
  static double drand48();
};

