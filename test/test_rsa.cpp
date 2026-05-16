#include "rsa.h"
#include "config.h"

#include <iostream>
#include <string>
#include <vector>

using secure_chat::DES_KEY_SIZE;
using secure_chat::RSA;
using secure_chat::RsaPublicKey;
using secure_chat::gcd64;
using secure_chat::isProbablePrime;
using secure_chat::modInverse;
using secure_chat::modPow;

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

    void testGcdAndModInverse(TestContext& ctx)
    {
        printDivider();
        std::cout << "[TEST GROUP] gcd / modInverse 测试\n";

        expectEqual(ctx, gcd64(48, 18), static_cast<std::uint64_t>(6), "gcd64(48,18)=6");
        expectEqual(ctx, gcd64(17, 3120), static_cast<std::uint64_t>(1), "17 与 3120 互素");

        const std::uint64_t d = modInverse(17, 3120);
        expectEqual(ctx, d, static_cast<std::uint64_t>(2753), "17 关于 3120 的逆元为 2753");
        expectEqual(ctx, (17 * d) % 3120, static_cast<std::uint64_t>(1), "e*d mod phi = 1");
    }

    void testModPow(TestContext& ctx)
    {
        printDivider();
        std::cout << "[TEST GROUP] 快速模幂测试\n";

        expectEqual(ctx, modPow(4, 13, 497), static_cast<std::uint64_t>(445), "4^13 mod 497 = 445");
        expectEqual(ctx, modPow(5, 0, 19), static_cast<std::uint64_t>(1), "5^0 mod 19 = 1");
        expectEqual(ctx, modPow(2, 10, 1000), static_cast<std::uint64_t>(24), "2^10 mod 1000 = 24");
    }

    void testPrimeCheck(TestContext& ctx)
    {
        printDivider();
        std::cout << "[TEST GROUP] Miller-Rabin 素性测试\n";

        expectTrue(ctx, isProbablePrime(65537), "65537 应识别为素数");
        expectTrue(ctx, isProbablePrime(32771), "32771 应识别为素数");
        expectTrue(ctx, !isProbablePrime(65535), "65535 应识别为合数");
        expectTrue(ctx, !isProbablePrime(100000), "100000 应识别为合数");
    }

    void testRsaIntegerRoundTrip(TestContext& ctx)
    {
        printDivider();
        std::cout << "[TEST GROUP] RSA 整数加解密往返测试\n";

        RSA rsa;
        expectTrue(ctx, rsa.generateKeyPair(16), "RSA 密钥对生成成功");

        const RsaPublicKey publicKey = rsa.getPublicKey();

        const std::vector<std::uint64_t> messages =
        {
            1, 65, 1024, 4096, 65535
        };

        for (std::uint64_t m : messages)
        {
            const std::uint64_t c = RSA::encryptInteger(m, publicKey);
            const std::uint64_t r = rsa.decryptInteger(c);

            expectEqual(ctx, r, m, "RSA integer round trip: " + std::to_string(m));
        }
    }

    void testDesKeyRoundTrip(TestContext& ctx)
    {
        printDivider();
        std::cout << "[TEST GROUP] DES 密钥 RSA 加解密测试\n";

        RSA rsa;
        expectTrue(ctx, rsa.generateKeyPair(16), "RSA 密钥对生成成功");

        const std::string desKey = "Ab12Cd34";
        expectEqual(ctx,
                    desKey.size(),
                    DES_KEY_SIZE,
                    "测试 DES 密钥长度为 8 字节");

        const std::vector<std::uint64_t> encrypted =
            RSA::encryptDesKey(desKey, rsa.getPublicKey());

        expectEqual(ctx,
                    encrypted.size(),
                    static_cast<std::size_t>(4),
                    "8 字节 DES 密钥拆成 4 个 RSA 分组");

        const std::string recovered = rsa.decryptDesKey(encrypted);

        expectEqual(ctx, recovered, desKey, "DES 密钥经过 RSA 加解密后完全恢复");
    }

} // namespace

int main()
{
    TestContext ctx;

    testGcdAndModInverse(ctx);
    testModPow(ctx);
    testPrimeCheck(ctx);
    testRsaIntegerRoundTrip(ctx);
    testDesKeyRoundTrip(ctx);

    printDivider();
    std::cout << "[SUMMARY] passed = " << ctx.passed
              << ", failed = " << ctx.failed << "\n";

    return ctx.failed == 0 ? 0 : 1;
}
