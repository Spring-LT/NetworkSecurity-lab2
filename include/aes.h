#pragma once

#include <string>
#include <vector>

namespace secure_chat
{
    /**
     * @brief AES-128 加解密（扩展版本）
     *
     * 密钥：16 字节（16 个字符）。
     * 模式：ECB（分组独立加解密），用于实验扩展演示。
     * 补位：PKCS#7（blockSize=16）。
     */
    class AES128
    {
    public:
        AES128();

        /**
         * @brief 设置 AES-128 密钥并完成轮密钥扩展
         * @param key 16 字节字符串密钥
         * @return 成功返回 true，否则返回 false
         */
        bool setKey(const std::string& key);

        /**
         * @brief AES-128 加密（ECB + PKCS#7 补位）
         * @param plaintext 明文字节数组
         * @return 密文字节数组；若密钥未设置或失败则返回空数组
         */
        std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext) const;

        /**
         * @brief AES-128 解密（ECB + PKCS#7 去补位）
         * @param ciphertext 密文字节数组（长度为 16 的整数倍）
         * @return 明文字节数组；若输入非法或密钥未设置则返回空数组
         */
        std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext) const;

    private:
        unsigned char roundKeys_[176] = {0}; // 11 * 16 bytes
        bool keyReady_ = false;
    };

} // namespace secure_chat
