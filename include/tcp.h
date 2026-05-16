#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace secure_chat
{
    /**
     * @brief 创建 TCP 服务端监听套接字
     *
     * 功能流程：
     * 1. socket() 创建流式套接字
     * 2. setsockopt() 设置 SO_REUSEADDR，避免端口短时间内无法重用
     * 3. bind() 绑定本地地址和端口
     * 4. listen() 开始监听
     *
     * @param port 监听端口
     * @return 成功返回监听 socket 文件描述符；失败时抛出 std::runtime_error
     */
    int createServerSocket(int port);

    /**
     * @brief 接受一个客户端连接
     *
     * 功能流程：
     * 1. accept() 阻塞等待客户端连接
     * 2. 返回新的通信 socket
     * 3. 输出客户端 IP 和端口，便于后续显示“谁连接了服务端”
     *
     * @param listenFd 服务端监听 socket
     * @param clientIp 输出参数，返回客户端 IP 字符串
     * @param clientPort 输出参数，返回客户端端口
     * @return 成功返回已连接的通信 socket；失败时抛出 std::runtime_error
     */
    int acceptClient(int listenFd, std::string& clientIp, int& clientPort);

    /**
     * @brief 创建 TCP 客户端套接字并连接到服务端
     *
     * 功能流程：
     * 1. socket() 创建流式套接字
     * 2. connect() 连接服务端
     *
     * @param serverIp 服务端 IP 地址，例如 "127.0.0.1"
     * @param port 服务端端口
     * @return 成功返回已连接的 socket；失败时抛出 std::runtime_error
     */
    int createClientSocket(const std::string& serverIp, int port);

    /**
     * @brief 保证把指定长度的数据全部发送出去
     *
     * 说明：
     * send() 一次调用不保证把所有数据全部发完，因此需要循环发送。
     *
     * @param sockfd 已连接 socket
     * @param data 待发送数据首地址
     * @param len 待发送总长度
     * @return 成功返回 true；失败或连接中断返回 false
     */
    bool sendAll(int sockfd, const unsigned char* data, std::size_t len);

    /**
     * @brief 保证从 socket 中完整接收指定长度的数据
     *
     * 说明：
     * recv() 一次调用不保证收到所需的全部字节，因此需要循环接收。
     * 这正是实验文档中 TotalRecv() 那类函数要解决的问题。
     *
     * @param sockfd 已连接 socket
     * @param buffer 接收缓冲区首地址
     * @param len 目标接收长度
     * @return 成功返回 true；若连接关闭或接收失败返回 false
     */
    bool recvAll(int sockfd, unsigned char* buffer, std::size_t len);

    /**
     * @brief 发送一个完整“消息包”
     *
     * 包格式：
     * [4 字节长度头（网络字节序）][实际数据]
     *
     * 说明：
     * 聊天消息经过 DES/AES 加密后是二进制数据，不能按 C 字符串处理，
     * 因此这里采用“长度头 + 数据体”的方式来进行消息边界管理。
     *
     * @param sockfd 已连接 socket
     * @param packet 待发送的完整数据包（通常是密文）
     * @return 成功返回 true，失败返回 false
     */
    bool sendPacket(int sockfd, const std::vector<unsigned char>& packet);

    /**
     * @brief 接收一个完整“消息包”
     *
     * 功能流程：
     * 1. 先接收 4 字节长度头
     * 2. 再根据长度接收完整数据体
     *
     * @param sockfd 已连接 socket
     * @param packet 输出参数，返回接收到的数据包
     * @return 成功返回 true；若连接关闭或接收失败返回 false
     */
    bool recvPacket(int sockfd, std::vector<unsigned char>& packet);

    /**
     * @brief 关闭 socket
     *
     * @param sockfd 目标 socket
     */
    void closeSocket(int sockfd);

} // namespace secure_chat
