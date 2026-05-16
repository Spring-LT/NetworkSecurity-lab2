#pragma once

#include <string>
#include <vector>

#include "rsa.h"

namespace secure_chat
{
    /**
     * @brief 生成 8 字节随机 DES 会话密钥
     */
    std::string generateRandomDesKey();

    /**
     * @brief 服务端发送 RSA 公钥
     */
    bool sendRsaPublicKey(int sockfd, const RsaPublicKey& publicKey);

    /**
     * @brief 客户端接收 RSA 公钥
     */
    bool recvRsaPublicKey(int sockfd, RsaPublicKey& publicKey);

    /**
     * @brief 客户端使用 RSA 公钥加密 DES 密钥并发送
     */
    bool sendEncryptedDesKey(int sockfd,
                             const std::string& desKey,
                             const RsaPublicKey& publicKey);

    /**
     * @brief 服务端接收 RSA 加密的 DES 密钥并解密
     */
    bool recvEncryptedDesKey(int sockfd,
                             const RSA& rsa,
                             std::string& desKey);

    /**
     * @brief 服务端完整密钥交换流程
     *
     * 1. 生成 RSA 公私钥对。
     * 2. 发送 RSA 公钥。
     * 3. 接收 RSA 加密的 DES 会话密钥。
     * 4. 使用私钥解密得到 DES 密钥。
     */
    std::string serverPerformRsaDesKeyExchange(int sockfd);

    /**
     * @brief 客户端完整密钥交换流程
     *
     * 1. 自动生成 DES 会话密钥。
     * 2. 接收服务端 RSA 公钥。
     * 3. 使用公钥加密 DES 密钥。
     * 4. 发送加密后的 DES 密钥。
     */
    std::string clientPerformRsaDesKeyExchange(int sockfd);

} // namespace secure_chat
