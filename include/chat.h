#pragma once

#include <string>
#include <vector>

#include "config.h"

namespace secure_chat
{
    /**
     * @brief 启动服务端
     *
     * 功能：
     * 1. 创建监听 socket
     * 2. 等待客户端连接
     * 3. 连接建立后进入加密聊天
     *
     * @param port 监听端口
     * @param key 加密密钥
    * @param algorithmType 算法类型（支持 DES / 3DES / AES-128）
     */
    void runServer(int port, const std::string& key, AlgorithmType algorithmType);

    /**
     * @brief 启动客户端
     *
     * 功能：
     * 1. 连接服务端
     * 2. 连接建立后进入加密聊天
     *
     * @param serverIp 服务端 IP
     * @param port 服务端端口
     * @param key 加密密钥
    * @param algorithmType 算法类型（支持 DES / 3DES / AES-128）
     */
    void runClient(const std::string& serverIp,
                   int port,
                   const std::string& key,
                   AlgorithmType algorithmType);

    /**
     * @brief 进入聊天主逻辑
     *
     * 功能：
     * 使用 fork() 实现全双工聊天。
     * - 父进程：接收消息、解密并显示
     * - 子进程：读取输入、加密并发送
     *
     * @param sockfd 已建立连接的 socket
     * @param peerName 对端名称或地址
     * @param key 加密密钥
     * @param algorithmType 算法类型
     */
    void secretChat(int sockfd,
                    const std::string& peerName,
                    const std::string& key,
                    AlgorithmType algorithmType);

    /**
     * @brief 接收循环
     *
     * 功能：
     * 1. 从 socket 接收完整密文包
     * 2. 调用解密函数得到明文
     * 3. 输出到屏幕
     * 4. 若收到 quit，则结束接收循环
        *
        * @param sockfd 已建立连接的 socket
        * @param peerName 对端名称或地址（用于打印提示）
        * @param key 加密密钥
        * @param algorithmType 算法类型
     */
    void chatReceiveLoop(int sockfd,
                         const std::string& peerName,
                         const std::string& key,
                         AlgorithmType algorithmType);

    /**
     * @brief 发送循环
     *
     * 功能：
     * 1. 从标准输入读取用户输入
     * 2. 调用加密函数得到密文
     * 3. 发送密文包
     * 4. 若输入 quit，则结束发送循环
        *
        * @param sockfd 已建立连接的 socket
        * @param key 加密密钥
        * @param algorithmType 算法类型
     */
    void chatSendLoop(int sockfd,
                      const std::string& key,
                      AlgorithmType algorithmType);

    /**
     * @brief 统一的消息加密接口
     *
     * @param message 明文字符串
     * @param key 密钥
     * @param algorithmType 算法类型
     * @return 加密后的二进制密文
     */
    std::vector<unsigned char> encryptMessage(const std::string& message,
                                              const std::string& key,
                                              AlgorithmType algorithmType);

    /**
     * @brief 统一的消息解密接口
     *
     * @param cipher 密文二进制数据
     * @param key 密钥
     * @param algorithmType 算法类型
     * @return 解密后的明文字符串
     */
    std::string decryptMessage(const std::vector<unsigned char>& cipher,
                               const std::string& key,
                               AlgorithmType algorithmType);

} // namespace secure_chat
