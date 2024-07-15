# net_connector

C++实现有线及无线的密码代填

自动搜索可连接的有线/无线，当前已连接网络有(已连接)标识，实时更新并通知网络状态

Qt 界面化操作



# 原理

无线实现原理：通过windows系统API，将账号密码写入xml文件

有线实现原理：通过winpcap抓包，捕获二层的802.1包，发出对应回包与其交互，填入账号密码



# 结构

net_connector：

​		public：共享库，包含json、openssl、winpcap、protocol(与ui通讯的json格式)

​		src：区分有线实现代码(ethernet)与无线实现代码(wifi)

提供了头文件net_connector_global.h与net_connector_define.h，库文件net_connector.dll的接口如下

```c++
bool __stdcall NetConnectorWifiInit();
bool __stdcall NetConnectorWifiDeInit();
bool __stdcall NetConnectorEthernetInit();
bool __stdcall NetConnectorEthernetDeInit();
bool __stdcall NetConnectorNetConnect(const char* ssid, const char* username, const char* pwd);
bool __stdcall NetConnectorNetDisconnect(const char* ssid);
void __stdcall NetConnectorSetNetEventCallBack(LPNetEventCallBack callback, void* user_data);
```



dll_caller：

​		Qt实现的调用工具，仅为dll的调用demo

# 效果

![image-20240715161740221](C:\Users\wangpeng\AppData\Roaming\Typora\typora-user-images\image-20240715161740221.png)





![image-20240715152349074](C:\Users\wangpeng\AppData\Roaming\Typora\typora-user-images\image-20240715152349074.png)



# 文档

详细实现细节可参考[C++实现802.1x客户端_1x认证客户端源代码-CSDN博客](https://blog.csdn.net/baidu_28572705/article/details/129669311)