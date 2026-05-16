#include "config.h"
#include "tdes.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using secure_chat::DES_BLOCK_SIZE;
using secure_chat::TripleDES;

namespace
{
    struct TestContext
    {
        int passed = 0;
        int failed = 0;
    };

    std::vector<unsigned char> stringToBytes(const std::string& s)
    {
        return std::vector<unsigned char>(s.begin(), s.end());
    }

    std::string bytesToString(const std::vector<unsigned char>& data)
    {
        return std::string(data.begin(), data.end());
    }

    std::string bytesToHex(const std::vector<unsigned char>& data)
    {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');

        for (std::size_t i = 0; i < data.size(); ++i)
        {
            oss << std::setw(2) << static_cast<unsigned int>(data[i]);
            if (i + 1 != data.size())
            {
                oss << ' ';
            }
        }

        return oss.str();
    }

    bool expectTrue(TestContext& ctx, bool condition, const std::string& testName)
    {
        if (condition)
        {
            ++ctx.passed;
            std::cout << "[PASS] " << testName << '\n';
            return true;
        }
        else
        {
            ++ctx.failed;
            std::cout << "[FAIL] " << testName << '\n';
            return false;
        }
    }

    bool expectEqual(TestContext& ctx,
                     const std::string& actual,
                     const std::string& expected,
                     const std::string& testName)
    {
        if (actual == expected)
        {
            ++ctx.passed;
            std::cout << "[PASS] " << testName << '\n';
            return true;
        }
        else
        {
            ++ctx.failed;
            std::cout << "[FAIL] " << testName << '\n';
            std::cout << "       expected: " << expected << '\n';
            std::cout << "       actual  : " << actual << '\n';
            return false;
        }
    }

    void printDivider()
    {
        std::cout << "--------------------------------------------------\n";
    }

    void testKeyValidation(TestContext& ctx)
    {
        printDivider();
        std::cout << "[TEST GROUP] 3DES 密钥格式测试\n";

        TripleDES tdes;
        expectTrue(ctx, tdes.setKey("12345678:abcdefgh"), "合法 key1:key2 格式应设置成功");
        expectTrue(ctx, !tdes.setKey("12345678"), "缺少分隔符应设置失败");
        expectTrue(ctx, !tdes.setKey("short:abcdefgh"), "key1 长度不足应失败");
        expectTrue(ctx, !tdes.setKey("12345678:short"), "key2 长度不足应失败");
    }

    void testRoundTrip(TestContext& ctx,
                       const std::string& key,
                       const std::string& plaintext,
                       const std::string& testName)
    {
        TripleDES enc;
        TripleDES dec;

        bool ok = true;
        ok &= expectTrue(ctx, enc.setKey(key), testName + " - 设置密钥成功");
        ok &= expectTrue(ctx, dec.setKey(key), testName + " - 第二个实例设置密钥成功");
        if (!ok)
        {
            return;
        }

        const std::vector<unsigned char> plainBytes = stringToBytes(plaintext);
        const std::vector<unsigned char> cipherBytes = enc.encrypt(plainBytes);

        expectTrue(ctx, !cipherBytes.empty(), testName + " - 加密结果非空");
        expectTrue(ctx,
                   (cipherBytes.size() % DES_BLOCK_SIZE) == 0,
                   testName + " - 密文长度为 8 的整数倍");

        const std::vector<unsigned char> recoveredBytes = dec.decrypt(cipherBytes);
        const std::string recoveredText = bytesToString(recoveredBytes);

        expectEqual(ctx, recoveredText, plaintext, testName + " - 解密后完全还原");

        std::cout << "       明文: " << plaintext << '\n';
        std::cout << "       密文(hex): " << bytesToHex(cipherBytes) << '\n';
    }

    void testTypicalMessages(TestContext& ctx)
    {
        printDivider();
        std::cout << "[TEST GROUP] 3DES 多组典型消息往返测试\n";

        const std::string key = "12345678:abcdefgh";

        testRoundTrip(ctx, key, "a", "长度 1 字符串测试");
        testRoundTrip(ctx, key, "1234567", "长度 7 字符串测试");
        testRoundTrip(ctx, key, "12345678", "长度 8 字符串测试");
        testRoundTrip(ctx, key, "Hello, 3DES chat!", "含空格与标点字符串测试");
        testRoundTrip(ctx, key, "quit", "quit 指令字符串测试");
        testRoundTrip(ctx, key, std::string(u8"你好，3DES扩展！"), "中文 UTF-8 字符串测试");
    }

} // namespace

int main()
{
    TestContext ctx;

    std::cout << "==================================================\n";
    std::cout << "3DES Unit Test Start\n";
    std::cout << "==================================================\n";

    testKeyValidation(ctx);
    testTypicalMessages(ctx);

    printDivider();
    std::cout << "[SUMMARY]\n";
    std::cout << "Passed: " << ctx.passed << '\n';
    std::cout << "Failed: " << ctx.failed << '\n';

    if (ctx.failed == 0)
    {
        std::cout << "[RESULT] ALL TESTS PASSED.\n";
        return 0;
    }

    std::cout << "[RESULT] SOME TESTS FAILED.\n";
    return 1;
}
