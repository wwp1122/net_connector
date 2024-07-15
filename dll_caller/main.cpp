#include "net_connector_caller.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    NetConnectorCaller w;
    w.show();
    return a.exec();
}
