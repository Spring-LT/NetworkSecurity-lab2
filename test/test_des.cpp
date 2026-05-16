#include "des.h"
#include "config.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using secure_chat::DES;
using secure_chat::DES_BLOCK_SIZE;

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
        std::cout << "[TEST GROUP] DES 密钥合法性测试\n";

        DES des;

        expectTrue(ctx, des.setKey("benbenmi"), "8 字节密钥应设置成功");
        expectTrue(ctx, !des.setKey("short"), "过短密钥应设置失败");
        expectTrue(ctx, !des.setKey("toolongkey"), "过长密钥应设置失败");
    }

    void testRoundTrip(TestContext& ctx,
                       const std::string& key,
                       const std::string& plaintext,
                       const std::string& testName)
    {
        DES des;
        DES des2;

        bool ok = true;
        ok &= expectTrue(ctx, des.setKey(key), testName + " - 设置密钥成功");
        ok &= expectTrue(ctx, des2.setKey(key), testName + " - 第二个实例设置密钥成功");

        if (!ok)
        {
            return;
        }

        const std::vector<unsigned char> plainBytes = stringToBytes(plaintext);
        const std::vector<unsigned char> cipherBytes = des.encrypt(plainBytes);

        expectTrue(ctx, !cipherBytes.empty(), testName + " - 加密结果非空");
        expectTrue(ctx,
                   (cipherBytes.size() % DES_BLOCK_SIZE) == 0,
                   testName + " - 密文长度为 8 的整数倍");

        const std::vector<unsigned char> recoveredBytes = des2.decrypt(cipherBytes);
        const std::string recoveredText = bytesToString(recoveredBytes);

        expectEqual(ctx, recoveredText, plaintext, testName + " - 解密后完全还原");

        std::cout << "       明文: " << plaintext << '\n';
        std::cout << "       密文(hex): " << bytesToHex(cipherBytes) << '\n';
    }

    void testDeterministicEncryption(TestContext& ctx)
    {
        printDivider();
        std::cout << "[TEST GROUP] 同一输入加密结果稳定性测试\n";

        DES des;
        expectTrue(ctx, des.setKey("benbenmi"), "设置固定测试密钥成功");

        const std::string plaintext = "Hello~I'm client~";
        const std::vector<unsigned char> plainBytes = stringToBytes(plaintext);

        const std::vector<unsigned char> cipher1 = des.encrypt(plainBytes);
        const std::vector<unsigned char> cipher2 = des.encrypt(plainBytes);

        expectTrue(ctx, cipher1 == cipher2, "同一明文同一密钥两次加密结果一致");

        std::cout << "       第一次密文(hex): " << bytesToHex(cipher1) << '\n';
        std::cout << "       第二次密文(hex): " << bytesToHex(cipher2) << '\n';
    }

    void testWrongKey(TestContext& ctx)
    {
        printDivider();
        std::cout << "[TEST GROUP] 错误密钥解密测试\n";

        DES encryptDes;
        DES decryptDes;

        bool ok = true;
        ok &= expectTrue(ctx, encryptDes.setKey("benbenmi"), "加密端设置正确密钥成功");
        ok &= expectTrue(ctx, decryptDes.setKey("abcdefgh"), "解密端设置错误密钥成功");

        if (!ok)
        {
            return;
        }

        const std::string plaintext = "Network Security Experiment";
        const std::vector<unsigned char> plainBytes = stringToBytes(plaintext);

        const std::vector<unsigned char> cipherBytes = encryptDes.encrypt(plainBytes);
        const std::vector<unsigned char> wrongRecoveredBytes = decryptDes.decrypt(cipherBytes);
        const std::string wrongRecoveredText = bytesToString(wrongRecoveredBytes);

        expectTrue(ctx,
                   wrongRecoveredText != plaintext,
                   "使用错误密钥时，解密结果不应等于原文");

        std::cout << "       原文: " << plaintext << '\n';
        std::cout << "       错误解密结果: " << wrongRecoveredText << '\n';
    }

    void testTypicalMessages(TestContext& ctx)
    {
        printDivider();
        std::cout << "[TEST GROUP] 多组典型消息往返测试\n";

        // 1 字节
        testRoundTrip(ctx, "benbenmi", "a", "长度 1 字符串测试");

        // 7 字节
        testRoundTrip(ctx, "benbenmi", "1234567", "长度 7 字符串测试");

        // 8 字节
        testRoundTrip(ctx, "benbenmi", "12345678", "长度 8 字符串测试");

        // 9 字节
        testRoundTrip(ctx, "benbenmi", "123456789", "长度 9 字符串测试");

        // 15 字节
        testRoundTrip(ctx, "benbenmi", "1234567890abcde", "长度 15 字符串测试");

        // 16 字节
        testRoundTrip(ctx, "benbenmi", "1234567890abcdef", "长度 16 字符串测试");

        // 带空格与标点
        testRoundTrip(ctx,
                      "benbenmi",
                      "Hello, DES chat program!",
                      "含空格与标点字符串测试");

        // 教材聊天场景常见字符串
        testRoundTrip(ctx,
                      "benbenmi",
                      "Hello~I'm client~",
                      "聊天消息字符串测试");

        // quit 指令
        testRoundTrip(ctx,
                      "benbenmi",
                      "quit",
                      "quit 指令字符串测试");

        // 中文 UTF-8 字符串
        testRoundTrip(ctx,
                      "benbenmi",
                      std::string(u8"你好，DES聊天实验！"),
                      "中文 UTF-8 字符串测试");
    }

} // namespace

int main()
{
    TestContext ctx;

    std::cout << "==================================================\n";
    std::cout << "DES Unit Test Start\n";
    std::cout << "==================================================\n";

    testKeyValidation(ctx);
    testTypicalMessages(ctx);
    testDeterministicEncryption(ctx);
    testWrongKey(ctx);

    printDivider();
    std::cout << "[SUMMARY]\n";
    std::cout << "Passed: " << ctx.passed << '\n';
    std::cout << "Failed: " << ctx.failed << '\n';

    if (ctx.failed == 0)
    {
        std::cout << "[RESULT] ALL TESTS PASSED.\n";
        return 0;
    }
    else
    {
        std::cout << "[RESULT] SOME TESTS FAILED.\n";
        return 1;
    }
}
