#pragma once
#include <string>
#include <functional>

typedef std::function<void(int, const std::string&)> LPNetNotifyCallBack;

class InternetManager {
public:
  virtual ~InternetManager() {};

  virtual bool Init(LPNetNotifyCallBack notification_cb) = 0;
  virtual void Release() = 0;

  virtual bool Connect(const std::string&, const std::string&, const std::string&) = 0;
  virtual bool Disconnect(const std::string&) = 0;
};