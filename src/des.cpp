#include "des.h"

#include <cstring>
#include <iostream>

namespace secure_chat
{
    namespace
    {
        // =========================================================
        // 1. 初始置换 IP（与实验文档中的 pc_first 对应）
        // =========================================================
        static const int IP_TABLE[64] =
        {
            58, 50, 42, 34, 26, 18, 10,  2,
            60, 52, 44, 36, 28, 20, 12,  4,
            62, 54, 46, 38, 30, 22, 14,  6,
            64, 56, 48, 40, 32, 24, 16,  8,
            57, 49, 41, 33, 25, 17,  9,  1,
            59, 51, 43, 35, 27, 19, 11,  3,
            61, 53, 45, 37, 29, 21, 13,  5,
            63, 55, 47, 39, 31, 23, 15,  7
        };

        // =========================================================
        // 2. 逆初始置换 IP^-1（与实验文档中的 pc_last 对应）
        // =========================================================
        static const int FP_TABLE[64] =
        {
            40,  8, 48, 16, 56, 24, 64, 32,
            39,  7, 47, 15, 55, 23, 63, 31,
            38,  6, 46, 14, 54, 22, 62, 30,
            37,  5, 45, 13, 53, 21, 61, 29,
            36,  4, 44, 12, 52, 20, 60, 28,
            35,  3, 43, 11, 51, 19, 59, 27,
            34,  2, 42, 10, 50, 18, 58, 26,
            33,  1, 41,  9, 49, 17, 57, 25
        };

        // =========================================================
        // 3. 选择扩展运算 E 盒（32 bit -> 48 bit）
        //    与实验文档中的 des_E 对应
        // =========================================================
        static const int E_TABLE[48] =
        {
            32,  1,  2,  3,  4,  5,
             4,  5,  6,  7,  8,  9,
             8,  9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,  1
        };

        // =========================================================
        // 4. P 置换（32 bit -> 32 bit）
        //    与实验文档中的 des_P 对应
        // =========================================================
        static const int P_TABLE[32] =
        {
            16,  7, 20, 21,
            29, 12, 28, 17,
             1, 15, 23, 26,
             5, 18, 31, 10,
             2,  8, 24, 14,
            32, 27,  3,  9,
            19, 13, 30,  6,
            22, 11,  4, 25
        };

        // =========================================================
        // 5. S 盒（8 个，每个 4 行 16 列）
        //    与实验文档中的 des_S 等价
        // =========================================================
        static const int S_BOX[8][4][16] =
        {
            // S1
            {
                {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
                { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
                { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
                {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
            },

            // S2
            {
                {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
                { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
                { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
                {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
            },

            // S3
            {
                {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
                {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
                {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
                { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
            },

            // S4
            {
                { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
                {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
                {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
                { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
            },

            // S5
            {
                { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
                {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
                { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
                {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
            },

            // S6
            {
                {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
                {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
                { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
                { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
            },

            // S7
            {
                { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
                {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
                { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
                { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
            },

            // S8
            {
                {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
                { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
                { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
                { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
            }
        };

        // =========================================================
        // 6. 密钥置换选择 PC-1（64 bit -> 56 bit）
        //
        // 注意：
        // 实验文档中将 PC-1 分成 keyleft[28] 和 keyright[28] 两部分描述。
        // 本实现采用标准合并写法，逻辑完全等价：
        // 前 28 位作为 C0，后 28 位作为 D0。
        // =========================================================
        static const int PC1_TABLE[56] =
        {
            57, 49, 41, 33, 25, 17,  9,
             1, 58, 50, 42, 34, 26, 18,
            10,  2, 59, 51, 43, 35, 27,
            19, 11,  3, 60, 52, 44, 36,

            63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
            14,  6, 61, 53, 45, 37, 29,
            21, 13,  5, 28, 20, 12,  4
        };

        // =========================================================
        // 7. 密钥循环左移位数表（与实验文档中的 lefttable 对应）
        // =========================================================
        static const int KEY_SHIFTS[16] =
        {
            1, 1, 2, 2,
            2, 2, 2, 2,
            1, 2, 2, 2,
            2, 2, 2, 1
        };

        // =========================================================
        // 8. 密钥置换选择 PC-2（56 bit -> 48 bit）
        //    与实验文档中的 keychoose 对应
        // =========================================================
        static const int PC2_TABLE[48] =
        {
            14, 17, 11, 24,  1,  5,
             3, 28, 15,  6, 21, 10,
            23, 19, 12,  4, 26,  8,
            16,  7, 27, 20, 13,  2,

            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };

    } // namespace

    DES::DES()
        : subKeys_{0}, keyReady_(false)
    {
    }

    DES::~DES() = default;

    bool DES::setKey(const std::string& key)
    {
        // 按实验要求，DES 密钥输入长度固定为 8 字节
        if (key.size() != DES_KEY_SIZE)
        {
            keyReady_ = false;
            return false;
        }

        generateSubKeys(reinterpret_cast<const unsigned char*>(key.data()));
        keyReady_ = true;
        return true;
    }

    std::vector<unsigned char> DES::encrypt(const std::vector<unsigned char>& plaintext) const
    {
        std::vector<unsigned char> cipher;

        if (!keyReady_)
        {
            return cipher;
        }

        // 按实验文档要求：明文不足 64 bit 的部分用 0 补齐
        const std::vector<unsigned char> padded = padPlaintext(plaintext);

        if (padded.empty())
        {
            return cipher;
        }

        cipher.resize(padded.size());

        // 每 8 字节作为一个 64 bit 分组分别加密
        for (std::size_t i = 0; i < padded.size(); i += DES_BLOCK_SIZE)
        {
            uint64_t block = bytesToUint64(&padded[i]);
            uint64_t encryptedBlock = encryptBlock(block);
            uint64ToBytes(encryptedBlock, &cipher[i]);
        }

        return cipher;
    }

    std::vector<unsigned char> DES::decrypt(const std::vector<unsigned char>& ciphertext) const
    {
        std::vector<unsigned char> plain;

        if (!keyReady_)
        {
            return plain;
        }

        // DES 密文长度必须是 8 的整数倍
        if (ciphertext.empty() || (ciphertext.size() % DES_BLOCK_SIZE) != 0)
        {
            return plain;
        }

        plain.resize(ciphertext.size());

        // 每 8 字节作为一个 64 bit 分组分别解密
        for (std::size_t i = 0; i < ciphertext.size(); i += DES_BLOCK_SIZE)
        {
            uint64_t block = bytesToUint64(&ciphertext[i]);
            uint64_t decryptedBlock = decryptBlock(block);
            uint64ToBytes(decryptedBlock, &plain[i]);
        }

        // 去除尾部 0 补齐
        return removeTrailingZeroPadding(plain);
    }

    std::vector<unsigned char> DES::encryptRawBlocks(const std::vector<unsigned char>& plaintext) const
    {
        std::vector<unsigned char> cipher;

        if (!keyReady_)
        {
            return cipher;
        }

        if (plaintext.empty() || (plaintext.size() % DES_BLOCK_SIZE) != 0)
        {
            return cipher;
        }

        cipher.resize(plaintext.size());

        for (std::size_t i = 0; i < plaintext.size(); i += DES_BLOCK_SIZE)
        {
            uint64_t block = bytesToUint64(&plaintext[i]);
            uint64_t encryptedBlock = encryptBlock(block);
            uint64ToBytes(encryptedBlock, &cipher[i]);
        }

        return cipher;
    }

    std::vector<unsigned char> DES::decryptRawBlocks(const std::vector<unsigned char>& ciphertext) const
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

        plain.resize(ciphertext.size());

        for (std::size_t i = 0; i < ciphertext.size(); i += DES_BLOCK_SIZE)
        {
            uint64_t block = bytesToUint64(&ciphertext[i]);
            uint64_t decryptedBlock = decryptBlock(block);
            uint64ToBytes(decryptedBlock, &plain[i]);
        }

        return plain;
    }

    void DES::generateSubKeys(const unsigned char key[DES_KEY_SIZE])
    {
        // =====================================================
        // 子密钥生成流程：
        // 1. 原始 64 bit 密钥先做 PC-1，得到 56 bit
        // 2. 将 56 bit 分为 C0 / D0 两部分，各 28 bit
        // 3. 每轮分别循环左移
        // 4. 拼接为 56 bit，再做 PC-2，得到本轮 48 bit 子密钥
        // 5. 共生成 16 个子密钥
        // =====================================================

        uint64_t rawKey = bytesToUint64(key);

        // PC-1：从 64 bit 中选出 56 bit，有效密钥位
        uint64_t permutedKey = permute(rawKey, PC1_TABLE, 56, 64);

        // 拆成两个 28 bit：C0 和 D0
        uint32_t c = static_cast<uint32_t>((permutedKey >> 28) & 0x0FFFFFFF);
        uint32_t d = static_cast<uint32_t>(permutedKey & 0x0FFFFFFF);

        for (int round = 0; round < 16; ++round)
        {
            // 按轮次要求进行 1 位或 2 位循环左移
            c = leftRotate28(c, KEY_SHIFTS[round]);
            d = leftRotate28(d, KEY_SHIFTS[round]);

            // 合并成 56 bit：高 28 位是 C，低 28 位是 D
            uint64_t cd = (static_cast<uint64_t>(c) << 28) | static_cast<uint64_t>(d);

            // PC-2：从 56 bit 中选出 48 bit，作为该轮子密钥
            subKeys_[round] = permute(cd, PC2_TABLE, 48, 56);
        }
    }

    uint64_t DES::encryptBlock(uint64_t block) const
    {
        // =====================================================
        // 单块 DES 加密流程严格按照实验文档：
        // 1. 初始置换 IP
        // 2. 分成 L0 / R0
        // 3. 进行 16 轮迭代：
        //      Li = Ri-1
        //      Ri = Li-1 xor f(Ri-1, Ki)
        // 4. 交换左右，得到 R16L16
        // 5. 做逆初始置换 IP^-1
        // =====================================================

        uint64_t ip = initialPermutation(block);

        uint32_t left  = static_cast<uint32_t>((ip >> 32) & 0xFFFFFFFFu);
        uint32_t right = static_cast<uint32_t>(ip & 0xFFFFFFFFu);

        for (int round = 0; round < 16; ++round)
        {
            uint32_t oldRight = right;

            // Ri = Li-1 xor f(Ri-1, Ki)
            right = left ^ feistelFunction(right, subKeys_[round]);

            // Li = Ri-1
            left = oldRight;
        }

        // 注意：DES 在 16 轮结束后要交换左右，组合成 R16L16
        uint64_t preOutput = (static_cast<uint64_t>(right) << 32) |
                              static_cast<uint64_t>(left);

        return finalPermutation(preOutput);
    }

    uint64_t DES::decryptBlock(uint64_t block) const
    {
        // =====================================================
        // DES 解密与加密结构相同，只是 16 轮子密钥使用顺序相反
        // =====================================================

        uint64_t ip = initialPermutation(block);

        uint32_t left  = static_cast<uint32_t>((ip >> 32) & 0xFFFFFFFFu);
        uint32_t right = static_cast<uint32_t>(ip & 0xFFFFFFFFu);

        for (int round = 15; round >= 0; --round)
        {
            uint32_t oldRight = right;

            // 解密时子密钥顺序相反
            right = left ^ feistelFunction(right, subKeys_[round]);
            left = oldRight;
        }

        uint64_t preOutput = (static_cast<uint64_t>(right) << 32) |
                              static_cast<uint64_t>(left);

        return finalPermutation(preOutput);
    }

    uint64_t DES::initialPermutation(uint64_t block) const
    {
        return permute(block, IP_TABLE, 64, 64);
    }

    uint64_t DES::finalPermutation(uint64_t block) const
    {
        return permute(block, FP_TABLE, 64, 64);
    }

    uint32_t DES::feistelFunction(uint32_t right, uint64_t subKey) const
    {
        // =====================================================
        // DES 轮函数 f(R, K) 的四个步骤：
        // 1. E 扩展：32 bit -> 48 bit
        // 2. 与该轮 48 bit 子密钥异或
        // 3. S 盒压缩：48 bit -> 32 bit
        // 4. P 置换：32 bit -> 32 bit
        // =====================================================

        // 第一步：E 扩展
        uint64_t expanded = permute(static_cast<uint64_t>(right), E_TABLE, 48, 32);

        // 第二步：与子密钥异或
        uint64_t xored = expanded ^ subKey;

        // 第三步：S 盒压缩
        uint32_t sBoxOutput = sBoxSubstitution(xored);

        // 第四步：P 置换
        uint32_t pOutput = static_cast<uint32_t>(permute(static_cast<uint64_t>(sBoxOutput),
                                                         P_TABLE,
                                                         32,
                                                         32));

        return pOutput;
    }

    uint64_t DES::permute(uint64_t input, const int* table, int tableSize, int inputBits) const
    {
        // =====================================================
        // 通用置换函数
        //
        // table[i] 表示：
        // “输出的第 i+1 位，取输入中的第 table[i] 位”
        //
        // 位编号规则：
        // 从左到右，从 1 开始编号
        // 即：
        // - 第 1 位是最高位（MSB）
        // - 第 inputBits 位是最低位（LSB）
        // =====================================================

        uint64_t output = 0;

        for (int i = 0; i < tableSize; ++i)
        {
            output <<= 1;

            // 计算源位在 input 中的偏移
            const int sourcePosFromLeft = table[i];
            const int shift = inputBits - sourcePosFromLeft;

            uint64_t bit = (input >> shift) & 0x1ULL;
            output |= bit;
        }

        return output;
    }

    uint32_t DES::sBoxSubstitution(uint64_t input48) const
    {
        // =====================================================
        // S 盒处理说明：
        // 48 bit 输入分为 8 组，每组 6 bit
        // 每组进入一个 S 盒，输出 4 bit
        // 最终得到 32 bit
        //
        // 每组 6 bit 的解释方式：
        // - 第 1 位和第 6 位组成行号（row）
        // - 中间 4 位组成列号（col）
        // =====================================================

        uint32_t output = 0;

        for (int i = 0; i < 8; ++i)
        {
            // 从高位到低位依次取 8 个 6 bit 分组
            uint64_t sixBits = (input48 >> (42 - 6 * i)) & 0x3FULL;

            // 行号由首尾两位组成
            int row = static_cast<int>(((sixBits & 0x20ULL) >> 4) | (sixBits & 0x01ULL));

            // 列号由中间 4 位组成
            int col = static_cast<int>((sixBits >> 1) & 0x0FULL);

            int sValue = S_BOX[i][row][col];

            output = (output << 4) | static_cast<uint32_t>(sValue);
        }

        return output;
    }

    uint32_t DES::leftRotate28(uint32_t value, int shift) const
    {
        // 只保留低 28 位
        value &= 0x0FFFFFFF;

        // 28 位循环左移
        return ((value << shift) | (value >> (28 - shift))) & 0x0FFFFFFF;
    }

    std::vector<unsigned char> DES::padPlaintext(const std::vector<unsigned char>& data) const
    {
        // 按实验要求使用 0 补齐到 8 字节整数倍
        if (data.empty())
        {
            return {};
        }

        std::vector<unsigned char> padded = data;
        std::size_t remainder = padded.size() % DES_BLOCK_SIZE;

        if (remainder != 0)
        {
            std::size_t paddingSize = DES_BLOCK_SIZE - remainder;
            padded.insert(padded.end(), paddingSize, static_cast<unsigned char>(0));
        }

        return padded;
    }

    std::vector<unsigned char> DES::removeTrailingZeroPadding(const std::vector<unsigned char>& data) const
    {
        std::vector<unsigned char> result = data;

        while (!result.empty() && result.back() == static_cast<unsigned char>(0))
        {
            result.pop_back();
        }

        return result;
    }

    uint64_t DES::bytesToUint64(const unsigned char bytes[DES_BLOCK_SIZE]) const
    {
        // 大端方式拼装：
        // bytes[0] 为最高字节，bytes[7] 为最低字节
        uint64_t value = 0;

        for (std::size_t i = 0; i < DES_BLOCK_SIZE; ++i)
        {
            value = (value << 8) | static_cast<uint64_t>(bytes[i]);
        }

        return value;
    }

    void DES::uint64ToBytes(uint64_t value, unsigned char out[DES_BLOCK_SIZE]) const
    {
        // 大端方式拆分：
        // out[0] 为最高字节，out[7] 为最低字节
        for (std::size_t i = DES_BLOCK_SIZE; i-- > 0;)
        {
            out[i] = static_cast<unsigned char>(value & 0xFFULL);
            value >>= 8;
        }
    }

} // namespace secure_chat
