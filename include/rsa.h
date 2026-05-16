#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace secure_chat
{
    /**
     * @brief RSA 公钥结构
     *
     * e：公开指数
     * n：模数
     */
    struct RsaPublicKey
    {
        std::uint64_t e = 0;
        std::uint64_t n = 0;
    };

    /**
     * @brief RSA 私钥结构
     *
     * d：私有指数
     * n：模数
     */
    struct RsaPrivateKey
    {
        std::uint64_t d = 0;
        std::uint64_t n = 0;
    };

    /**
     * @brief RSA 密钥对结构
     *
     * 为了便于实验报告展示，保留 p、q、phi 等中间参数。
     * 实际通信中只发送 publicKey，privateKey 只保存在服务端。
     */
    struct RsaKeyPair
    {
        RsaPublicKey publicKey;
        RsaPrivateKey privateKey;

        std::uint64_t p = 0;
        std::uint64_t q = 0;
        std::uint64_t phi = 0;
    };

    /**
     * @brief RSA 算法类
     *
     * 本实验中 RSA 只用于分发 8 字节 DES 会话密钥，
     * 不直接加密聊天正文。
     */
    class RSA
    {
    public:
        RSA();

        /**
         * @brief 生成 RSA 公私钥对
         *
         * @param primeBits p 和 q 的位数，默认 16 bit。
         *                  本实验将 DES 密钥拆成 16 bit 分组加密，
         *                  因此 16 bit 素数生成的 n 足够覆盖每个明文分组。
         * @return 成功返回 true，失败返回 false
         */
        bool generateKeyPair(int primeBits = 16);

        /**
         * @brief 获取公钥
         */
        RsaPublicKey getPublicKey() const;

        /**
         * @brief 获取私钥
         */
        RsaPrivateKey getPrivateKey() const;

        /**
         * @brief 获取完整密钥对，便于调试和实验报告展示
         */
        RsaKeyPair getKeyPair() const;

        /**
         * @brief 使用 RSA 公钥加密单个整数
         */
        static std::uint64_t encryptInteger(std::uint64_t plain,
                                            const RsaPublicKey& key);

        /**
         * @brief 使用当前对象私钥解密单个整数
         */
        std::uint64_t decryptInteger(std::uint64_t cipher) const;

        /**
         * @brief 使用 RSA 公钥加密 8 字节 DES 密钥
         *
         * 处理方式：
         * 1. 将 8 字节 DES 密钥拆成 4 个 16 bit 明文分组。
         * 2. 分别执行 RSA 加密。
         * 3. 返回 4 个 RSA 密文整数。
         */
        static std::vector<std::uint64_t> encryptDesKey(const std::string& desKey,
                                                        const RsaPublicKey& key);

        /**
         * @brief 使用当前对象私钥解密 RSA 密文，恢复 8 字节 DES 密钥
         */
        std::string decryptDesKey(const std::vector<std::uint64_t>& cipherChunks) const;

    private:
        RsaKeyPair keyPair_;
        bool ready_ = false;
    };

    /**
     * @brief 求最大公约数
     */
    std::uint64_t gcd64(std::uint64_t a, std::uint64_t b);

    /**
     * @brief 快速模幂，计算 base^exp mod mod
     */
    std::uint64_t modPow(std::uint64_t base,
                         std::uint64_t exp,
                         std::uint64_t mod);

    /**
     * @brief 求 e 关于 phi 的乘法逆元
     */
    std::uint64_t modInverse(std::uint64_t e, std::uint64_t phi);

    /**
     * @brief Miller-Rabin 素性测试
     */
    bool isProbablePrime(std::uint64_t n, int rounds = 8);

    /**
     * @brief 生成指定位数的随机素数
     */
    std::uint64_t randomPrime(int bits);

} // namespace secure_chat
