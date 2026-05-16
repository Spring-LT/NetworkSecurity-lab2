#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "config.h"

namespace secure_chat
{
    /**
     * @brief DES 加解密类
     *
     * 说明：
     * 1. 本类严格围绕实验要求实现标准 DES 结构。
     * 2. 数据分组长度为 64 bit（8 字节）。
     * 3. 密钥输入长度为 64 bit（8 字节），其中有效密钥位为 56 bit。
     * 4. 明文不足 8 字节时，按实验文档要求使用 0 补齐。
     * 5. 解密后会去掉尾部因 0 补齐产生的 '\0'。
     *
     * 适用场景：
     * - 本实验的字符串加密解密
     * - 后续 TCP 聊天模块中的消息加密与解密
     */
    class DES
    {
    public:
        DES();
        ~DES();

        /**
         * @brief 设置 DES 密钥，并生成 16 轮子密钥
         * @param key 8 字节字符串密钥
         * @return 成功返回 true，否则返回 false
         */
        bool setKey(const std::string& key);

        /**
         * @brief 对任意长度明文字节流进行 DES 加密
         * @param plaintext 明文字节数组
         * @return 密文字节数组；若密钥未设置则返回空数组
         */
        std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext) const;

        /**
         * @brief 对 DES 密文字节流进行解密
         * @param ciphertext 密文字节数组，长度必须为 8 的整数倍
         * @return 解密后的明文字节数组；若输入非法或密钥未设置则返回空数组
         */
        std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext) const;

        /**
         * @brief 对齐分组的“原始块”加密（不做补位）
         *
         * 说明：
         * - 输入长度必须为 8 的整数倍
         * - 不执行 0 补齐
         * - 适用于 3DES 等需要在中间态保留完整二进制块的场景
         */
        std::vector<unsigned char> encryptRawBlocks(const std::vector<unsigned char>& plaintext) const;

        /**
         * @brief 对齐分组的“原始块”解密（不去除尾部补位）
         *
         * 说明：
         * - 输入长度必须为 8 的整数倍
         * - 不移除任何 padding 字节（例如 0 补齐产生的 0x00）
         */
        std::vector<unsigned char> decryptRawBlocks(const std::vector<unsigned char>& ciphertext) const;

    private:
        // 16 轮子密钥，每轮 48 bit，这里统一存放在 uint64_t 低 48 位中
        uint64_t subKeys_[16];

        // 标记密钥是否已经成功设置
        bool keyReady_;

    private:
        /**
         * @brief 根据 8 字节原始密钥生成 16 轮子密钥
         * @param key 原始 8 字节密钥
         */
        void generateSubKeys(const unsigned char key[DES_KEY_SIZE]);

        /**
         * @brief 单个 64 bit 分组加密
         * @param block 64 bit 明文块
         * @return 64 bit 密文块
         */
        uint64_t encryptBlock(uint64_t block) const;

        /**
         * @brief 单个 64 bit 分组解密
         * @param block 64 bit 密文块
         * @return 64 bit 明文块
         */
        uint64_t decryptBlock(uint64_t block) const;

        /**
         * @brief 初始置换 IP
         */
        uint64_t initialPermutation(uint64_t block) const;

        /**
         * @brief 逆初始置换 IP^-1
         */
        uint64_t finalPermutation(uint64_t block) const;

        /**
         * @brief DES 轮函数 f(R, K) = P(S(E(R) xor K))
         * @param right 32 bit 右半部分
         * @param subKey 48 bit 轮子密钥（存放于 uint64_t 低 48 位）
         * @return 32 bit 轮函数输出
         */
        uint32_t feistelFunction(uint32_t right, uint64_t subKey) const;

        /**
         * @brief 通用置换函数
         *
         * 说明：
         * table 中的序号采用 DES 标准中的“从左到右从 1 开始编号”方式。
         * 例如 table[i] = 1 表示取输入最高位。
         *
         * @param input 输入比特串
         * @param table 置换表
         * @param tableSize 置换输出位数
         * @param inputBits 输入位数
         * @return 置换结果（对齐到低位）
         */
        uint64_t permute(uint64_t input, const int* table, int tableSize, int inputBits) const;

        /**
         * @brief S 盒压缩：48 bit -> 32 bit
         * @param input48 48 bit 输入，存于 uint64_t 低 48 位
         * @return 32 bit 输出
         */
        uint32_t sBoxSubstitution(uint64_t input48) const;

        /**
         * @brief 28 bit 循环左移
         * @param value 仅低 28 位有效
         * @param shift 左移位数（1 或 2）
         * @return 左移后的 28 bit 结果
         */
        uint32_t leftRotate28(uint32_t value, int shift) const;

        /**
         * @brief 明文按实验要求进行 0 补齐
         * @param data 原始明文字节流
         * @return 补齐后的字节流，长度为 8 的整数倍
         */
        std::vector<unsigned char> padPlaintext(const std::vector<unsigned char>& data) const;

        /**
         * @brief 去除因 0 补齐带来的尾部 '\0'
         *
         * 注意：
         * 本实验主要处理字符串聊天消息，不处理任意二进制文件，
         * 因此可以安全地去除尾部 0 填充。
         */
        std::vector<unsigned char> removeTrailingZeroPadding(const std::vector<unsigned char>& data) const;

        /**
         * @brief 将 8 字节数组按大端方式组装为 64 bit 整数
         */
        uint64_t bytesToUint64(const unsigned char bytes[DES_BLOCK_SIZE]) const;

        /**
         * @brief 将 64 bit 整数按大端方式拆分为 8 字节
         */
        void uint64ToBytes(uint64_t value, unsigned char out[DES_BLOCK_SIZE]) const;
    };

} // namespace secure_chat
