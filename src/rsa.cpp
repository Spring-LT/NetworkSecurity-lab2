#include "rsa.h"

#include <algorithm>
#include <chrono>
#include <random>
#include <stdexcept>

#include "config.h"

namespace secure_chat
{
    namespace
    {
        /**
         * @brief 生成 64 bit 随机数引擎
         */
        std::mt19937_64& globalRng()
        {
            static std::random_device rd;
            static std::mt19937_64 rng(
                static_cast<std::uint64_t>(rd()) ^
                static_cast<std::uint64_t>(
                    std::chrono::high_resolution_clock::now().time_since_epoch().count()
                )
            );
            return rng;
        }

        /**
         * @brief 模乘，避免 a*b 在 64 bit 下溢出
         *
         * 1. 使用 GCC/Clang 支持的 __uint128_t 保存中间乘积。
         * 2. 再对 mod 取模。
         * 3. 转回 uint64_t。
         */
        std::uint64_t mulMod(std::uint64_t a,
                             std::uint64_t b,
                             std::uint64_t mod)
        {
            return static_cast<std::uint64_t>(
                (static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b)) % mod
            );
        }

        /**
         * @brief 扩展欧几里得算法
         *
         * 1. 递归求 ax + by = gcd(a,b)。
         * 2. 返回最大公约数。
         * 3. 通过引用参数返回 x、y。
         */
        std::int64_t extendedGcd(std::int64_t a,
                                 std::int64_t b,
                                 std::int64_t& x,
                                 std::int64_t& y)
        {
            if (b == 0)
            {
                x = 1;
                y = 0;
                return a;
            }

            std::int64_t x1 = 0;
            std::int64_t y1 = 0;
            const std::int64_t g = extendedGcd(b, a % b, x1, y1);

            x = y1;
            y = x1 - (a / b) * y1;
            return g;
        }

        /**
         * @brief 生成 [low, high] 范围内的随机 uint64_t
         */
        std::uint64_t randomUint64(std::uint64_t low, std::uint64_t high)
        {
            std::uniform_int_distribution<std::uint64_t> dist(low, high);
            return dist(globalRng());
        }

        /**
         * @brief 判断一个数是否为偶数
         */
        bool isEven(std::uint64_t n)
        {
            return (n & 1ULL) == 0ULL;
        }

    } // namespace

    RSA::RSA() = default;

    std::uint64_t gcd64(std::uint64_t a, std::uint64_t b)
    {
        // 1. 反复用 b 替代 a，用 a%b 替代 b。
        // 2. 当 b 为 0 时，a 即为最大公约数。
        // 3. 返回最终结果。
        while (b != 0)
        {
            const std::uint64_t r = a % b;
            a = b;
            b = r;
        }

        return a;
    }

    std::uint64_t modPow(std::uint64_t base,
                         std::uint64_t exp,
                         std::uint64_t mod)
    {
        if (mod == 0)
        {
            throw std::invalid_argument("modPow(): mod must not be zero");
        }

        // 1. 将底数先化到模空间内。
        // 2. 使用二进制快速幂。
        // 3. 每次乘法使用 mulMod 防止中间乘积溢出。
        std::uint64_t result = 1 % mod;
        base %= mod;

        while (exp > 0)
        {
            if ((exp & 1ULL) != 0ULL)
            {
                result = mulMod(result, base, mod);
            }

            base = mulMod(base, base, mod);
            exp >>= 1ULL;
        }

        return result;
    }

    std::uint64_t modInverse(std::uint64_t e, std::uint64_t phi)
    {
        if (phi == 0)
        {
            return 0;
        }

        // 1. 使用扩展欧几里得求 e*x + phi*y = gcd(e, phi)。
        // 2. 若 gcd 不为 1，则逆元不存在。
        // 3. 若 x 为负，将其调整到 [0, phi)。
        std::int64_t x = 0;
        std::int64_t y = 0;

        const std::int64_t g = extendedGcd(static_cast<std::int64_t>(e),
                                           static_cast<std::int64_t>(phi),
                                           x,
                                           y);

        if (g != 1)
        {
            return 0;
        }

        std::int64_t ans = x % static_cast<std::int64_t>(phi);
        if (ans < 0)
        {
            ans += static_cast<std::int64_t>(phi);
        }

        return static_cast<std::uint64_t>(ans);
    }

    bool isProbablePrime(std::uint64_t n, int rounds)
    {
        // 1. 先处理小数和偶数。
        // 2. 将 n-1 写成 d * 2^s 的形式。
        // 3. 多轮随机取底数 a 做 Miller-Rabin 测试。
        if (n < 2)
        {
            return false;
        }

        static const std::uint64_t smallPrimes[] =
        {
            2ULL, 3ULL, 5ULL, 7ULL, 11ULL, 13ULL,
            17ULL, 19ULL, 23ULL, 29ULL, 31ULL, 37ULL
        };

        for (std::uint64_t p : smallPrimes)
        {
            if (n == p)
            {
                return true;
            }
            if (n % p == 0)
            {
                return false;
            }
        }

        if (isEven(n))
        {
            return false;
        }

        std::uint64_t d = n - 1;
        int s = 0;

        while ((d & 1ULL) == 0ULL)
        {
            d >>= 1ULL;
            ++s;
        }

        for (int i = 0; i < rounds; ++i)
        {
            const std::uint64_t a = randomUint64(2, n - 2);
            std::uint64_t x = modPow(a, d, n);

            if (x == 1 || x == n - 1)
            {
                continue;
            }

            bool witnessPassed = false;

            for (int r = 1; r < s; ++r)
            {
                x = mulMod(x, x, n);

                if (x == n - 1)
                {
                    witnessPassed = true;
                    break;
                }
            }

            if (!witnessPassed)
            {
                return false;
            }
        }

        return true;
    }

    std::uint64_t randomPrime(int bits)
    {
        if (bits < 4 || bits > 31)
        {
            throw std::invalid_argument("randomPrime(): bits must be in [4, 31]");
        }

        // 1. 根据 bits 计算候选数范围。
        // 2. 强制最高位为 1，保证位数足够。
        // 3. 强制最低位为 1，保证候选数为奇数。
        const std::uint64_t low = (1ULL << (bits - 1));
        const std::uint64_t high = (1ULL << bits) - 1ULL;

        while (true)
        {
            std::uint64_t candidate = randomUint64(low, high);
            candidate |= low;
            candidate |= 1ULL;

            if (isProbablePrime(candidate))
            {
                return candidate;
            }
        }
    }

    bool RSA::generateKeyPair(int primeBits)
    {
        try
        {
            // 1. 随机生成两个不同素数 p、q。
            std::uint64_t p = randomPrime(primeBits);
            std::uint64_t q = randomPrime(primeBits);

            while (q == p)
            {
                q = randomPrime(primeBits);
            }

            // 2. 计算 n 与 phi(n)。
            const std::uint64_t n = p * q;
            const std::uint64_t phi = (p - 1) * (q - 1);

            // 3. 优先选择常用公开指数 65537。
            std::uint64_t e = 65537ULL;

            if (e >= phi || gcd64(e, phi) != 1)
            {
                e = 3;
                while (e < phi && gcd64(e, phi) != 1)
                {
                    e += 2;
                }
            }

            if (e >= phi)
            {
                return false;
            }

            // 4. 计算私钥指数 d，使 e*d ≡ 1 mod phi。
            const std::uint64_t d = modInverse(e, phi);
            if (d == 0)
            {
                return false;
            }

            // 5. 保存密钥对。
            keyPair_.publicKey = RsaPublicKey{e, n};
            keyPair_.privateKey = RsaPrivateKey{d, n};
            keyPair_.p = p;
            keyPair_.q = q;
            keyPair_.phi = phi;
            ready_ = true;

            return true;
        }
        catch (...)
        {
            ready_ = false;
            return false;
        }
    }

    RsaPublicKey RSA::getPublicKey() const
    {
        if (!ready_)
        {
            throw std::runtime_error("RSA public key is not ready");
        }

        return keyPair_.publicKey;
    }

    RsaPrivateKey RSA::getPrivateKey() const
    {
        if (!ready_)
        {
            throw std::runtime_error("RSA private key is not ready");
        }

        return keyPair_.privateKey;
    }

    RsaKeyPair RSA::getKeyPair() const
    {
        if (!ready_)
        {
            throw std::runtime_error("RSA key pair is not ready");
        }

        return keyPair_;
    }

    std::uint64_t RSA::encryptInteger(std::uint64_t plain,
                                      const RsaPublicKey& key)
    {
        if (key.e == 0 || key.n == 0)
        {
            throw std::invalid_argument("RSA::encryptInteger(): invalid public key");
        }

        if (plain >= key.n)
        {
            throw std::invalid_argument("RSA::encryptInteger(): plain must be smaller than n");
        }

        // RSA 加密：C = M^e mod n
        return modPow(plain, key.e, key.n);
    }

    std::uint64_t RSA::decryptInteger(std::uint64_t cipher) const
    {
        if (!ready_)
        {
            throw std::runtime_error("RSA private key is not ready");
        }

        if (cipher >= keyPair_.privateKey.n)
        {
            throw std::invalid_argument("RSA::decryptInteger(): cipher must be smaller than n");
        }

        // RSA 解密：M = C^d mod n
        return modPow(cipher, keyPair_.privateKey.d, keyPair_.privateKey.n);
    }

    std::vector<std::uint64_t> RSA::encryptDesKey(const std::string& desKey,
                                                  const RsaPublicKey& key)
    {
        if (desKey.size() != DES_KEY_SIZE)
        {
            throw std::invalid_argument("RSA::encryptDesKey(): DES key must be 8 bytes");
        }

        // 1. DES 密钥为 8 字节。
        // 2. 每 2 字节合成一个 16 bit 整数。
        // 3. 对 4 个整数分别执行 RSA 加密。
        std::vector<std::uint64_t> cipherChunks;
        cipherChunks.reserve(4);

        for (std::size_t i = 0; i < desKey.size(); i += 2)
        {
            const std::uint64_t high =
                static_cast<unsigned char>(desKey[i]);

            const std::uint64_t low =
                static_cast<unsigned char>(desKey[i + 1]);

            const std::uint64_t plainChunk = (high << 8ULL) | low;
            cipherChunks.push_back(encryptInteger(plainChunk, key));
        }

        return cipherChunks;
    }

    std::string RSA::decryptDesKey(const std::vector<std::uint64_t>& cipherChunks) const
    {
        if (cipherChunks.size() != 4)
        {
            throw std::invalid_argument("RSA::decryptDesKey(): encrypted DES key must contain 4 chunks");
        }

        // 1. 分别解密 4 个 RSA 密文整数。
        // 2. 每个整数拆回 2 字节。
        // 3. 拼接得到 8 字节 DES 会话密钥。
        std::string desKey;
        desKey.reserve(DES_KEY_SIZE);

        for (std::uint64_t cipherChunk : cipherChunks)
        {
            const std::uint64_t plainChunk = decryptInteger(cipherChunk);

            const char high =
                static_cast<char>((plainChunk >> 8ULL) & 0xFFULL);

            const char low =
                static_cast<char>(plainChunk & 0xFFULL);

            desKey.push_back(high);
            desKey.push_back(low);
        }

        return desKey;
    }

} // namespace secure_chat
