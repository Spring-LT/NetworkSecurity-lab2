#pragma once

#include <string>
#include <vector>

namespace secure_chat
{
    /**
     * @brief 3DES (EDE) 加解密（扩展版本）
     *
     * 密钥格式："key1:key2"，其中 key1/key2 均为 8 字节。
     *
     * 模式：ECB（分组独立加解密），用于实验扩展演示。
     * 补位：PKCS#7（blockSize=8）。
     */
    class TripleDES
    {
    public:
        TripleDES();

        /**
         * @brief 设置 3DES 密钥
         * @param key 密钥格式："key1:key2"（key1/key2 各 8 字节）
         * @return 成功返回 true，否则返回 false
         */
        bool setKey(const std::string& key);

        /**
         * @brief 3DES 加密（EDE，ECB + PKCS#7 补位）
         * @param plaintext 明文字节数组
         * @return 密文字节数组；若密钥未设置或失败则返回空数组
         */
        std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext) const;

        /**
         * @brief 3DES 解密（EDE 反向，ECB + PKCS#7 去补位）
         * @param ciphertext 密文字节数组（长度为 8 的整数倍）
         * @return 明文字节数组；若输入非法或密钥未设置则返回空数组
         */
        std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext) const;

    private:
        std::string key1_;
        std::string key2_;
        bool keyReady_ = false;
    };

} // namespace secure_chat
