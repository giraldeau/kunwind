#include <QString>
#include <QtTest>

#include <kunwind.h>
#include <sys/ioctl.h>

#define KUNWIND_DEBUG_PATH "/proc/kunwind_debug"

class TestsKunwind : public QObject
{
    Q_OBJECT

public:
    TestsKunwind();

private Q_SLOTS:
    void testCase1();

};

TestsKunwind::TestsKunwind()
{
}

void TestsKunwind::testCase1()
{
    struct kunwind_debug_info info;
    info.x = 42;
    info.y = 0;

    qDebug() << info.x << info.y;
    QFile f(KUNWIND_DEBUG_PATH);
    Q_ASSERT(f.open(QIODevice::ReadWrite));
    ioctl(f.handle(), KUNWIND_DEBUG_IOCTL, &info);
    QVERIFY2(info.x == info.y, "value should be copied");
    qDebug() << info.x << info.y;
}

QTEST_APPLESS_MAIN(TestsKunwind)

#include "tst_testskunwind.moc"
