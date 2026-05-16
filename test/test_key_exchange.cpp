#include "key_exchange.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "config.h"
#include "utils.h"

using secure_chat::AlgorithmType;
using secure_chat::clientPerformRsaDesKeyExchange;
using secure_chat::serverPerformRsaDesKeyExchange;
using secure_chat::validateKeyForAlgorithm;

namespace
{
    struct TestContext
    {
        int passed = 0;
        int failed = 0;
    };

    bool expectTrue(TestContext& ctx,
                    bool condition,
                    const std::string& name)
    {
        if (condition)
        {
            ++ctx.passed;
            std::cout << "[PASS] " << name << "\n";
            return true;
        }

        ++ctx.failed;
        std::cout << "[FAIL] " << name << "\n";
        return false;
    }

    template <typename T>
    bool expectEqual(TestContext& ctx,
                     const T& actual,
                     const T& expected,
                     const std::string& name)
    {
        if (actual == expected)
        {
            ++ctx.passed;
            std::cout << "[PASS] " << name << "\n";
            return true;
        }

        ++ctx.failed;
        std::cout << "[FAIL] " << name << "\n";
        std::cout << "       expected: " << expected << "\n";
        std::cout << "       actual  : " << actual << "\n";
        return false;
    }

    void printDivider()
    {
        std::cout << "--------------------------------------------------\n";
    }

    void closeFd(int fd)
    {
        if (fd >= 0)
        {
            ::close(fd);
        }
    }

    void testKeyExchangeRoundTrip(TestContext& ctx)
    {
        printDivider();
        std::cout << "[TEST GROUP] RSA-DES 自动密钥交换测试\n";

        int fds[2] = {-1, -1};

        // 1. 使用 socketpair 在本机模拟一条全双工连接。
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        {
            expectTrue(ctx, false, "socketpair 创建失败");
            return;
        }

        std::string serverKey;
        std::string clientKey;

        std::exception_ptr serverError = nullptr;
        std::exception_ptr clientError = nullptr;

        // 2. 服务端线程：生成 RSA 公私钥，发送公钥，接收并解密 DES 密钥。
        std::thread serverThread([&]()
        {
            try
            {
                serverKey = serverPerformRsaDesKeyExchange(fds[0]);
            }
            catch (...)
            {
                serverError = std::current_exception();
            }
        });

        // 3. 客户端线程：生成 DES 密钥，接收公钥，加密发送 DES 密钥。
        std::thread clientThread([&]()
        {
            try
            {
                clientKey = clientPerformRsaDesKeyExchange(fds[1]);
            }
            catch (...)
            {
                clientError = std::current_exception();
            }
        });

        serverThread.join();
        clientThread.join();

        closeFd(fds[0]);
        closeFd(fds[1]);

        expectTrue(ctx, serverError == nullptr, "服务端密钥交换流程无异常");
        expectTrue(ctx, clientError == nullptr, "客户端密钥交换流程无异常");

        std::string reason;
        expectTrue(ctx,
                   validateKeyForAlgorithm(serverKey, AlgorithmType::DES, &reason),
                   "服务端解密得到合法 DES 密钥");

        expectTrue(ctx,
                   validateKeyForAlgorithm(clientKey, AlgorithmType::DES, &reason),
                   "客户端生成合法 DES 密钥");

        expectEqual(ctx, serverKey, clientKey, "服务端与客户端最终 DES 会话密钥一致");
    }

} // namespace

int main()
{
    TestContext ctx;

    testKeyExchangeRoundTrip(ctx);

    printDivider();
    std::cout << "[SUMMARY] passed = " << ctx.passed
              << ", failed = " << ctx.failed << "\n";

    return ctx.failed == 0 ? 0 : 1;
}
