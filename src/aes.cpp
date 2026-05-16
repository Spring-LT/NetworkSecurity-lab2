#include "aes.h"

#include <cstddef>
#include <cstdint>

#include "config.h"

namespace secure_chat
{
    namespace
    {
        // AES-128 分组大小固定为 16 字节。
        constexpr std::size_t AES_BLOCK_BYTES = 16;

        // AES S-box（ByteSub 查表）。
        static const unsigned char SBOX[256] = {
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
        };

        // AES 逆 S-box（解密时的逆 ByteSub 查表）。
        static const unsigned char INV_SBOX[256] = {
            0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
            0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
            0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
            0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
            0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
            0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
            0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
            0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
            0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
            0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
            0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
            0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
            0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
            0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
            0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
            0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
        };

        // KeyExpansion 中使用的轮常量 Rcon（仅用于每生成一个新轮密钥的首字节）。
        static const unsigned char RCON[11] = {
            0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
        };

        // GF(2^8) 上的 xtime：乘以 x（即 2），并按 AES 的不可约多项式 0x11B 约简。
        unsigned char xtime(unsigned char x)
        {
            return static_cast<unsigned char>((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
        }

        // GF(2^8) 乘法（MixColumns / InvMixColumns 会用到）。
        unsigned char mul(unsigned char a, unsigned char b)
        {
            unsigned char res = 0;
            while (b)
            {
                if (b & 1)
                {
                    res ^= a;
                }
                a = xtime(a);
                b >>= 1;
            }
            return res;
        }

        void subBytes(unsigned char state[16])
        {
            // ByteSub：逐字节过 S-box。
            for (int i = 0; i < 16; ++i)
            {
                state[i] = SBOX[state[i]];
            }
        }

        void invSubBytes(unsigned char state[16])
        {
            // 逆 ByteSub：逐字节过逆 S-box。
            for (int i = 0; i < 16; ++i)
            {
                state[i] = INV_SBOX[state[i]];
            }
        }

        // 状态矩阵 state 的存储约定：列优先（column-major）
        // 也就是 state[row + 4 * col]，与 AES 标准描述一致。
        void shiftRows(unsigned char state[16])
        {
            unsigned char tmp[16];
            // Row 0: no shift
            tmp[0]  = state[0];  tmp[4]  = state[4];  tmp[8]  = state[8];  tmp[12] = state[12];
            // Row 1: shift left by 1
            tmp[1]  = state[5];  tmp[5]  = state[9];  tmp[9]  = state[13]; tmp[13] = state[1];
            // Row 2: shift left by 2
            tmp[2]  = state[10]; tmp[6]  = state[14]; tmp[10] = state[2];  tmp[14] = state[6];
            // Row 3: shift left by 3
            tmp[3]  = state[15]; tmp[7]  = state[3];  tmp[11] = state[7];  tmp[15] = state[11];

            for (int i = 0; i < 16; ++i)
            {
                state[i] = tmp[i];
            }
        }

        void invShiftRows(unsigned char state[16])
        {
            unsigned char tmp[16];
            // Row 0
            tmp[0]  = state[0];  tmp[4]  = state[4];  tmp[8]  = state[8];  tmp[12] = state[12];
            // Row 1: shift right by 1
            tmp[1]  = state[13]; tmp[5]  = state[1];  tmp[9]  = state[5];  tmp[13] = state[9];
            // Row 2: shift right by 2
            tmp[2]  = state[10]; tmp[6]  = state[14]; tmp[10] = state[2];  tmp[14] = state[6];
            // Row 3: shift right by 3
            tmp[3]  = state[7];  tmp[7]  = state[11]; tmp[11] = state[15]; tmp[15] = state[3];

            for (int i = 0; i < 16; ++i)
            {
                state[i] = tmp[i];
            }
        }

        void mixColumns(unsigned char state[16])
        {
            // MixColumns：对每一列做固定矩阵乘法。
            for (int c = 0; c < 4; ++c)
            {
                const int i = 4 * c;
                unsigned char a0 = state[i + 0];
                unsigned char a1 = state[i + 1];
                unsigned char a2 = state[i + 2];
                unsigned char a3 = state[i + 3];

                state[i + 0] = static_cast<unsigned char>(mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3);
                state[i + 1] = static_cast<unsigned char>(a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3);
                state[i + 2] = static_cast<unsigned char>(a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3));
                state[i + 3] = static_cast<unsigned char>(mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2));
            }
        }

        void invMixColumns(unsigned char state[16])
        {
            // 逆 MixColumns：对每一列乘以逆矩阵。
            for (int c = 0; c < 4; ++c)
            {
                const int i = 4 * c;
                unsigned char a0 = state[i + 0];
                unsigned char a1 = state[i + 1];
                unsigned char a2 = state[i + 2];
                unsigned char a3 = state[i + 3];

                state[i + 0] = static_cast<unsigned char>(mul(a0, 0x0e) ^ mul(a1, 0x0b) ^ mul(a2, 0x0d) ^ mul(a3, 0x09));
                state[i + 1] = static_cast<unsigned char>(mul(a0, 0x09) ^ mul(a1, 0x0e) ^ mul(a2, 0x0b) ^ mul(a3, 0x0d));
                state[i + 2] = static_cast<unsigned char>(mul(a0, 0x0d) ^ mul(a1, 0x09) ^ mul(a2, 0x0e) ^ mul(a3, 0x0b));
                state[i + 3] = static_cast<unsigned char>(mul(a0, 0x0b) ^ mul(a1, 0x0d) ^ mul(a2, 0x09) ^ mul(a3, 0x0e));
            }
        }

        void addRoundKey(unsigned char state[16], const unsigned char* roundKey)
        {
            // AddRoundKey：与当前轮密钥逐字节异或。
            for (int i = 0; i < 16; ++i)
            {
                state[i] ^= roundKey[i];
            }
        }

        void keyExpansion(const unsigned char key[16], unsigned char roundKeys[176])
        {
            // AES-128 KeyExpansion：由初始 16 字节密钥扩展出 11 轮密钥（共 176 字节）。
            // Copy original key
            for (int i = 0; i < 16; ++i)
            {
                roundKeys[i] = key[i];
            }

            int bytesGenerated = 16;
            int rconIter = 1;
            unsigned char temp[4];

            while (bytesGenerated < 176)
            {
                for (int i = 0; i < 4; ++i)
                {
                    temp[i] = roundKeys[bytesGenerated - 4 + i];
                }

                if ((bytesGenerated % 16) == 0)
                {
                    // 每生成一个新轮密钥的首个 4 字节时，需要做：RotWord + SubWord + Rcon。
                    // RotWord
                    unsigned char t = temp[0];
                    temp[0] = temp[1];
                    temp[1] = temp[2];
                    temp[2] = temp[3];
                    temp[3] = t;

                    // SubWord
                    temp[0] = SBOX[temp[0]];
                    temp[1] = SBOX[temp[1]];
                    temp[2] = SBOX[temp[2]];
                    temp[3] = SBOX[temp[3]];

                    // Rcon
                    temp[0] ^= RCON[rconIter++];
                }

                for (int i = 0; i < 4; ++i)
                {
                    roundKeys[bytesGenerated] = static_cast<unsigned char>(roundKeys[bytesGenerated - 16] ^ temp[i]);
                    ++bytesGenerated;
                }
            }
        }

        void encryptBlock(const unsigned char in[16], unsigned char out[16], const unsigned char roundKeys[176])
        {
            // 单块 AES-128 加密：
            // 初始 AddRoundKey
            // 9 轮：SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
            // 最后一轮：SubBytes -> ShiftRows -> AddRoundKey
            unsigned char state[16];
            for (int i = 0; i < 16; ++i)
            {
                state[i] = in[i];
            }

            addRoundKey(state, roundKeys);

            for (int round = 1; round <= 9; ++round)
            {
                subBytes(state);
                shiftRows(state);
                mixColumns(state);
                addRoundKey(state, roundKeys + round * 16);
            }

            subBytes(state);
            shiftRows(state);
            addRoundKey(state, roundKeys + 10 * 16);

            for (int i = 0; i < 16; ++i)
            {
                out[i] = state[i];
            }
        }

        void decryptBlock(const unsigned char in[16], unsigned char out[16], const unsigned char roundKeys[176])
        {
            // 单块 AES-128 解密：
            // 初始 AddRoundKey(最后一轮密钥)
            // 9 轮：InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
            // 最后一轮：InvShiftRows -> InvSubBytes -> AddRoundKey(初始密钥)
            unsigned char state[16];
            for (int i = 0; i < 16; ++i)
            {
                state[i] = in[i];
            }

            addRoundKey(state, roundKeys + 10 * 16);

            for (int round = 9; round >= 1; --round)
            {
                invShiftRows(state);
                invSubBytes(state);
                addRoundKey(state, roundKeys + round * 16);
                invMixColumns(state);
            }

            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, roundKeys);

            for (int i = 0; i < 16; ++i)
            {
                out[i] = state[i];
            }
        }

        std::vector<unsigned char> pkcs7Pad(const std::vector<unsigned char>& input, std::size_t blockSize)
        {
            // PKCS#7：即使刚好对齐也要补一整块，保证解密可无歧义去补位。
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
            // PKCS#7 去补位：检查末尾 padLen 个字节是否都等于 padLen。
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

    AES128::AES128() = default;

    bool AES128::setKey(const std::string& key)
    {
        // 实验约定：AES-128 密钥为 16 字节（16 个字符）。
        if (key.size() != AES_KEY_SIZE)
        {
            keyReady_ = false;
            return false;
        }

        unsigned char rawKey[16];
        for (int i = 0; i < 16; ++i)
        {
            rawKey[i] = static_cast<unsigned char>(key[static_cast<std::size_t>(i)]);
        }

        keyExpansion(rawKey, roundKeys_);
        keyReady_ = true;
        return true;
    }

    std::vector<unsigned char> AES128::encrypt(const std::vector<unsigned char>& plaintext) const
    {
        // ECB + PKCS#7：每块独立加密，仅用于实验扩展演示。
        std::vector<unsigned char> cipher;
        if (!keyReady_)
        {
            return cipher;
        }

        const std::vector<unsigned char> padded = pkcs7Pad(plaintext, AES_BLOCK_BYTES);
        if (padded.empty())
        {
            return cipher;
        }

        cipher.resize(padded.size());

        for (std::size_t i = 0; i < padded.size(); i += AES_BLOCK_BYTES)
        {
            encryptBlock(&padded[i], &cipher[i], roundKeys_);
        }

        return cipher;
    }

    std::vector<unsigned char> AES128::decrypt(const std::vector<unsigned char>& ciphertext) const
    {
        // ECB 解密后执行 PKCS#7 去补位。
        std::vector<unsigned char> plain;
        if (!keyReady_)
        {
            return plain;
        }

        if (ciphertext.empty() || (ciphertext.size() % AES_BLOCK_BYTES) != 0)
        {
            return plain;
        }

        plain.resize(ciphertext.size());

        for (std::size_t i = 0; i < ciphertext.size(); i += AES_BLOCK_BYTES)
        {
            decryptBlock(&ciphertext[i], &plain[i], roundKeys_);
        }

        return pkcs7Unpad(plain, AES_BLOCK_BYTES);
    }

} // namespace secure_chat
