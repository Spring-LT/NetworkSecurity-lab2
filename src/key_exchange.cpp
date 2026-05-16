#include "key_exchange.h"

#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>

#include "config.h"
#include "tcp.h"
#include "utils.h"

namespace secure_chat
{
    namespace
    {
        constexpr char RSA_PUBLIC_KEY_MAGIC[4] = {'R', 'P', 'K', '1'};
        constexpr char ENCRYPTED_DES_KEY_MAGIC[4] = {'E', 'D', 'K', '1'};

        /**
         * @brief 向字节数组追加 4 字节 magic
         */
        void appendMagic(std::vector<unsigned char>& buffer, const char magic[4])
        {
            for (int i = 0; i < 4; ++i)
            {
                buffer.push_back(static_cast<unsigned char>(magic[i]));
            }
        }

        /**
         * @brief 检查字节数组中的 magic
         */
        bool checkMagic(const std::vector<unsigned char>& buffer,
                        const char magic[4])
        {
            if (buffer.size() < 4)
            {
                return false;
            }

            for (int i = 0; i < 4; ++i)
            {
                if (buffer[static_cast<std::size_t>(i)] !=
                    static_cast<unsigned char>(magic[i]))
                {
                    return false;
                }
            }

            return true;
        }

        /**
         * @brief 按大端序追加 uint32_t
         */
        void appendUint32(std::vector<unsigned char>& buffer, std::uint32_t value)
        {
            buffer.push_back(static_cast<unsigned char>((value >> 24U) & 0xFFU));
            buffer.push_back(static_cast<unsigned char>((value >> 16U) & 0xFFU));
            buffer.push_back(static_cast<unsigned char>((value >> 8U) & 0xFFU));
            buffer.push_back(static_cast<unsigned char>(value & 0xFFU));
        }

        /**
         * @brief 按大端序追加 uint64_t
         */
        void appendUint64(std::vector<unsigned char>& buffer, std::uint64_t value)
        {
            for (int i = 7; i >= 0; --i)
            {
                buffer.push_back(
                    static_cast<unsigned char>((value >> (static_cast<unsigned>(i) * 8U)) & 0xFFULL)
                );
            }
        }

        /**
         * @brief 从字节数组中读取 uint32_t
         */
        bool readUint32(const std::vector<unsigned char>& buffer,
                        std::size_t& offset,
                        std::uint32_t& value)
        {
            if (offset + 4 > buffer.size())
            {
                return false;
            }

            value = 0;
            value |= static_cast<std::uint32_t>(buffer[offset]) << 24U;
            value |= static_cast<std::uint32_t>(buffer[offset + 1]) << 16U;
            value |= static_cast<std::uint32_t>(buffer[offset + 2]) << 8U;
            value |= static_cast<std::uint32_t>(buffer[offset + 3]);

            offset += 4;
            return true;
        }

        /**
         * @brief 从字节数组中读取 uint64_t
         */
        bool readUint64(const std::vector<unsigned char>& buffer,
                        std::size_t& offset,
                        std::uint64_t& value)
        {
            if (offset + 8 > buffer.size())
            {
                return false;
            }

            value = 0;

            for (int i = 0; i < 8; ++i)
            {
                value <<= 8ULL;
                value |= static_cast<std::uint64_t>(buffer[offset + static_cast<std::size_t>(i)]);
            }

            offset += 8;
            return true;
        }

    } // namespace

    std::string generateRandomDesKey()
    {
        // 1. 为了实验截图可读性，随机密钥采用可打印字符。
        // 2. 每次生成 8 字节，满足 DES 密钥长度要求。
        // 3. 正式运行界面不直接打印密钥明文。
        static const char charset[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";

        static std::random_device rd;
        static std::mt19937 gen(rd());

        std::uniform_int_distribution<std::size_t> dist(0, sizeof(charset) - 2);

        std::string key;
        key.reserve(DES_KEY_SIZE);

        for (std::size_t i = 0; i < DES_KEY_SIZE; ++i)
        {
            key.push_back(charset[dist(gen)]);
        }

        return key;
    }

    bool sendRsaPublicKey(int sockfd, const RsaPublicKey& publicKey)
    {
        // 公钥包格式：
        // [4 bytes magic = RPK1][8 bytes e][8 bytes n]
        if (publicKey.e == 0 || publicKey.n == 0)
        {
            return false;
        }

        std::vector<unsigned char> packet;
        packet.reserve(20);

        appendMagic(packet, RSA_PUBLIC_KEY_MAGIC);
        appendUint64(packet, publicKey.e);
        appendUint64(packet, publicKey.n);

        return sendPacket(sockfd, packet);
    }

    bool recvRsaPublicKey(int sockfd, RsaPublicKey& publicKey)
    {
        std::vector<unsigned char> packet;

        if (!recvPacket(sockfd, packet))
        {
            return false;
        }

        if (packet.size() != 20 || !checkMagic(packet, RSA_PUBLIC_KEY_MAGIC))
        {
            return false;
        }

        std::size_t offset = 4;
        std::uint64_t e = 0;
        std::uint64_t n = 0;

        if (!readUint64(packet, offset, e))
        {
            return false;
        }

        if (!readUint64(packet, offset, n))
        {
            return false;
        }

        if (e == 0 || n == 0)
        {
            return false;
        }

        publicKey.e = e;
        publicKey.n = n;
        return true;
    }

    bool sendEncryptedDesKey(int sockfd,
                             const std::string& desKey,
                             const RsaPublicKey& publicKey)
    {
        if (desKey.size() != DES_KEY_SIZE)
        {
            return false;
        }

        std::vector<std::uint64_t> cipherChunks;

        try
        {
            cipherChunks = RSA::encryptDesKey(desKey, publicKey);
        }
        catch (...)
        {
            return false;
        }

        // 加密 DES 密钥包格式：
        // [4 bytes magic = EDK1][4 bytes chunkCount][8 bytes C0]...[8 bytes C3]
        std::vector<unsigned char> packet;
        packet.reserve(4 + 4 + cipherChunks.size() * 8);

        appendMagic(packet, ENCRYPTED_DES_KEY_MAGIC);
        appendUint32(packet, static_cast<std::uint32_t>(cipherChunks.size()));

        for (std::uint64_t cipher : cipherChunks)
        {
            appendUint64(packet, cipher);
        }

        return sendPacket(sockfd, packet);
    }

    bool recvEncryptedDesKey(int sockfd,
                             const RSA& rsa,
                             std::string& desKey)
    {
        std::vector<unsigned char> packet;

        if (!recvPacket(sockfd, packet))
        {
            return false;
        }

        if (packet.size() < 8 || !checkMagic(packet, ENCRYPTED_DES_KEY_MAGIC))
        {
            return false;
        }

        std::size_t offset = 4;
        std::uint32_t count = 0;

        if (!readUint32(packet, offset, count))
        {
            return false;
        }

        if (count != 4)
        {
            return false;
        }

        if (packet.size() != 4 + 4 + static_cast<std::size_t>(count) * 8)
        {
            return false;
        }

        std::vector<std::uint64_t> cipherChunks;
        cipherChunks.reserve(count);

        for (std::uint32_t i = 0; i < count; ++i)
        {
            std::uint64_t cipher = 0;

            if (!readUint64(packet, offset, cipher))
            {
                return false;
            }

            cipherChunks.push_back(cipher);
        }

        try
        {
            desKey = rsa.decryptDesKey(cipherChunks);
        }
        catch (...)
        {
            return false;
        }

        return desKey.size() == DES_KEY_SIZE;
    }

    std::string serverPerformRsaDesKeyExchange(int sockfd)
    {
        // 1. 服务端生成 RSA 公私钥对。
        RSA rsa;
        if (!rsa.generateKeyPair(16))
        {
            throw std::runtime_error("RSA key pair generation failed");
        }

        const RsaKeyPair keyPair = rsa.getKeyPair();

        std::cout << "[RSA] Key pair generated.\n";
        std::cout << "[RSA] Public key: e=" << keyPair.publicKey.e
                  << ", n=" << keyPair.publicKey.n << "\n";
        std::cout << "[RSA] Private key is kept only on server. [hidden]\n";

        // 2. 服务端只发送公钥，不发送私钥。
        if (!sendRsaPublicKey(sockfd, keyPair.publicKey))
        {
            throw std::runtime_error("send RSA public key failed");
        }

        std::cout << "[RSA] Public key sent to client.\n";

        // 3. 服务端接收 RSA 加密后的 DES 会话密钥。
        std::string desKey;

        if (!recvEncryptedDesKey(sockfd, rsa, desKey))
        {
            throw std::runtime_error("receive encrypted DES key failed");
        }

        // 4. 服务端解密得到 DES 会话密钥。
        std::string reason;
        if (!validateKeyForAlgorithm(desKey, AlgorithmType::DES, &reason))
        {
            throw std::runtime_error("decrypted DES key is invalid: " + reason);
        }

        std::cout << "[RSA] DES session key decrypted successfully. [hidden]\n";
        return desKey;
    }

    std::string clientPerformRsaDesKeyExchange(int sockfd)
    {
        // 1. 客户端自动生成 8 字节 DES 会话密钥。
        const std::string desKey = generateRandomDesKey();

        std::string reason;
        if (!validateKeyForAlgorithm(desKey, AlgorithmType::DES, &reason))
        {
            throw std::runtime_error("generated DES key is invalid: " + reason);
        }

        std::cout << "[DES] Random DES session key generated. [hidden]\n";

        // 2. 客户端接收服务端 RSA 公钥。
        RsaPublicKey publicKey;

        if (!recvRsaPublicKey(sockfd, publicKey))
        {
            throw std::runtime_error("receive RSA public key failed");
        }

        std::cout << "[RSA] Server public key received: e=" << publicKey.e
                  << ", n=" << publicKey.n << "\n";

        // 3. 客户端使用公钥加密 DES 会话密钥并发送。
        if (!sendEncryptedDesKey(sockfd, desKey, publicKey))
        {
            throw std::runtime_error("send encrypted DES key failed");
        }

        std::cout << "[RSA] DES session key encrypted and sent.\n";
        return desKey;
    }

} // namespace secure_chat
