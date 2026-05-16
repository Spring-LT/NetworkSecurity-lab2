#include "tdes.h"

#include <cstddef>
#include <stdexcept>

#include "config.h"
#include "des.h"

namespace secure_chat
{
    namespace
    {
        // 解析 3DES 密钥格式："key1:key2"。
        // 其中 key1/key2 各 8 字节，用于 EDE 中的 K1/K2。
        bool splitTwoKeys(const std::string& key, std::string& k1, std::string& k2)
        {
            const std::size_t pos = key.find(':');
            if (pos == std::string::npos)
            {
                return false;
            }

            k1 = key.substr(0, pos);
            k2 = key.substr(pos + 1);

            return (k1.size() == DES_KEY_SIZE) && (k2.size() == DES_KEY_SIZE);
        }

        std::vector<unsigned char> pkcs7Pad(const std::vector<unsigned char>& input, std::size_t blockSize)
        {
            // PKCS#7：填充字节的值等于填充长度；对齐时也补一整块。
            if (blockSize == 0)
            {
                return {};
            }

            std::vector<unsigned char> out = input;
            const std::size_t rem = out.size() % blockSize;
            const std::size_t padLen = (rem == 0) ? blockSize : (blockSize - rem);

            out.insert(out.end(), padLen, static_cast<unsigned char>(padLen));
            return out;
        }

        std::vector<unsigned char> pkcs7Unpad(const std::vector<unsigned char>& input, std::size_t blockSize)
        {
            // PKCS#7 去补位：校验末尾 padLen 个字节是否均等于 padLen。
            if (input.empty() || blockSize == 0 || (input.size() % blockSize) != 0)
            {
                return {};
            }

            const unsigned char pad = input.back();
            const std::size_t padLen = static_cast<std::size_t>(pad);
            if (padLen == 0 || padLen > blockSize || padLen > input.size())
            {
                return {};
            }

            for (std::size_t i = 0; i < padLen; ++i)
            {
                if (input[input.size() - 1 - i] != pad)
                {
                    return {};
                }
            }

            return std::vector<unsigned char>(input.begin(), input.end() - static_cast<std::ptrdiff_t>(padLen));
        }

    } // namespace

    TripleDES::TripleDES() = default;

    bool TripleDES::setKey(const std::string& key)
    {
        std::string k1;
        std::string k2;
        if (!splitTwoKeys(key, k1, k2))
        {
            keyReady_ = false;
            return false;
        }

        key1_ = k1;
        key2_ = k2;
        keyReady_ = true;
        return true;
    }

    std::vector<unsigned char> TripleDES::encrypt(const std::vector<unsigned char>& plaintext) const
    {
        std::vector<unsigned char> cipher;
        if (!keyReady_)
        {
            return cipher;
        }

        DES des1;
        DES des2;
        if (!des1.setKey(key1_) || !des2.setKey(key2_))
        {
            return cipher;
        }

        const std::vector<unsigned char> padded = pkcs7Pad(plaintext, DES_BLOCK_SIZE);
        if (padded.empty())
        {
            return cipher;
        }

        // 3DES EDE：C = E(K1, D(K2, E(K1, P)))
        // 这里使用 DES 的 rawBlocks 接口，避免中间态被“去除尾部 0”之类的规则破坏。
        const std::vector<unsigned char> stage1 = des1.encryptRawBlocks(padded);
        if (stage1.empty())
        {
            return cipher;
        }

        const std::vector<unsigned char> stage2 = des2.decryptRawBlocks(stage1);
        if (stage2.empty())
        {
            return cipher;
        }

        const std::vector<unsigned char> stage3 = des1.encryptRawBlocks(stage2);
        return stage3;
    }

    std::vector<unsigned char> TripleDES::decrypt(const std::vector<unsigned char>& ciphertext) const
    {
        std::vector<unsigned char> plain;
        if (!keyReady_)
        {
            return plain;
        }

        if (ciphertext.empty() || (ciphertext.size() % DES_BLOCK_SIZE) != 0)
        {
            return plain;
        }

        DES des1;
        DES des2;
        if (!des1.setKey(key1_) || !des2.setKey(key2_))
        {
            return plain;
        }

        // 3DES EDE 解密反向：P = D(K1, E(K2, D(K1, C)))
        const std::vector<unsigned char> stage1 = des1.decryptRawBlocks(ciphertext);
        if (stage1.empty())
        {
            return plain;
        }

        const std::vector<unsigned char> stage2 = des2.encryptRawBlocks(stage1);
        if (stage2.empty())
        {
            return plain;
        }

        const std::vector<unsigned char> stage3 = des1.decryptRawBlocks(stage2);
        if (stage3.empty())
        {
            return plain;
        }

        return pkcs7Unpad(stage3, DES_BLOCK_SIZE);
    }

} // namespace secure_chat
