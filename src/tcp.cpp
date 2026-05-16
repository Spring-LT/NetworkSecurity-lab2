#include "tcp.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <limits>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"
#include "utils.h"

namespace secure_chat
{
    namespace
    {
        // 与实验文档中的示例保持一致：服务端监听队列长度设为 5
        constexpr int LISTEN_BACKLOG = 5;

        /**
         * @brief 生成带 errno 描述的异常信息
         */
        std::runtime_error makeSocketError(const std::string& action)
        {
            return std::runtime_error(action + " failed: " + std::string(std::strerror(errno)));
        }
    } // namespace

    int createServerSocket(int port)
    {
        // =========================================================
        // 第一步：创建 TCP 流式套接字
        // domain   = AF_INET   -> IPv4
        // type     = SOCK_STREAM -> TCP
        // protocol = 0         -> 让系统自动选择对应协议
        // =========================================================
        int listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listenFd < 0)
        {
            throw makeSocketError("socket()");
        }

        // =========================================================
        // 第二步：设置地址重用
        //
        // 说明：
        // 如果服务端异常退出后立即重启，端口可能还处于 TIME_WAIT 状态，
        // 直接 bind 可能失败。设置 SO_REUSEADDR 可以提高实验时的可用性。
        // =========================================================
        int opt = 1;
        if (::setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            closeSocket(listenFd);
            throw makeSocketError("setsockopt(SO_REUSEADDR)");
        }

        // =========================================================
        // 第三步：构造本地地址并 bind
        // sin_addr.s_addr = INADDR_ANY 表示监听本机所有网卡地址
        // =========================================================
        sockaddr_in localAddr;
        std::memset(&localAddr, 0, sizeof(localAddr));
        localAddr.sin_family = AF_INET;
        localAddr.sin_port = htons(static_cast<uint16_t>(port));
        localAddr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (::bind(listenFd,
                   reinterpret_cast<sockaddr*>(&localAddr),
                   sizeof(localAddr)) < 0)
        {
            closeSocket(listenFd);
            throw makeSocketError("bind()");
        }

        // =========================================================
        // 第四步：进入监听状态
        // =========================================================
        if (::listen(listenFd, LISTEN_BACKLOG) < 0)
        {
            closeSocket(listenFd);
            throw makeSocketError("listen()");
        }

        return listenFd;
    }

    int acceptClient(int listenFd, std::string& clientIp, int& clientPort)
    {
        sockaddr_in remoteAddr;
        std::memset(&remoteAddr, 0, sizeof(remoteAddr));
        socklen_t addrLen = static_cast<socklen_t>(sizeof(remoteAddr));

        int connFd = -1;

        // =========================================================
        // accept() 可能会因为信号中断返回 -1 且 errno=EINTR，
        // 这种情况不是致命错误，应当重试。
        // =========================================================
        while (true)
        {
            connFd = ::accept(listenFd,
                              reinterpret_cast<sockaddr*>(&remoteAddr),
                              &addrLen);

            if (connFd >= 0)
            {
                break;
            }

            if (errno == EINTR)
            {
                continue;
            }

            throw makeSocketError("accept()");
        }

        // =========================================================
        // 将客户端地址转换为字符串形式，便于后续打印日志：
        // 例如：192.168.1.23
        // =========================================================
        char ipBuffer[INET_ADDRSTRLEN] = {0};
        const char* res = ::inet_ntop(AF_INET,
                                      &remoteAddr.sin_addr,
                                      ipBuffer,
                                      sizeof(ipBuffer));

        if (res != nullptr)
        {
            clientIp = ipBuffer;
        }
        else
        {
            clientIp = "unknown";
        }

        clientPort = static_cast<int>(ntohs(remoteAddr.sin_port));
        return connFd;
    }

    int createClientSocket(const std::string& serverIp, int port)
    {
        // =========================================================
        // 第一步：创建客户端套接字
        // =========================================================
        int sockfd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
            throw makeSocketError("socket()");
        }

        // =========================================================
        // 第二步：构造服务端地址
        // inet_pton 用于把 "127.0.0.1" 这样的字符串 IP 转成二进制地址
        // =========================================================
        sockaddr_in serverAddr;
        std::memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(static_cast<uint16_t>(port));

        int ptonResult = ::inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr);
        if (ptonResult <= 0)
        {
            closeSocket(sockfd);

            if (ptonResult == 0)
            {
                throw std::runtime_error("inet_pton() failed: invalid IPv4 address format");
            }
            else
            {
                throw makeSocketError("inet_pton()");
            }
        }

        // =========================================================
        // 第三步：连接服务端
        // =========================================================
        if (::connect(sockfd,
                      reinterpret_cast<sockaddr*>(&serverAddr),
                      sizeof(serverAddr)) < 0)
        {
            closeSocket(sockfd);
            throw makeSocketError("connect()");
        }

        return sockfd;
    }

    bool sendAll(int sockfd, const unsigned char* data, std::size_t len)
    {
        // 长度为 0，视为发送成功
        if (len == 0)
        {
            return true;
        }

        if (data == nullptr)
        {
            return false;
        }

        std::size_t totalSent = 0;

        while (totalSent < len)
        {
            // =====================================================
            // send() 一次不一定把所有数据发送完，所以要循环发。
            // 为了避免向已关闭 socket 写入时触发 SIGPIPE 导致进程退出，
            // Linux 下优先使用 MSG_NOSIGNAL。
            // =====================================================
            int flags = 0;
#ifdef MSG_NOSIGNAL
            flags = MSG_NOSIGNAL;
#endif

            ssize_t sent = ::send(sockfd,
                                  data + totalSent,
                                  len - totalSent,
                                  flags);

            if (sent > 0)
            {
                totalSent += static_cast<std::size_t>(sent);
                continue;
            }

            // 被信号中断，重试
            if (sent < 0 && errno == EINTR)
            {
                continue;
            }

            // 其余情况视为发送失败
            return false;
        }

        return true;
    }

    bool recvAll(int sockfd, unsigned char* buffer, std::size_t len)
    {
        // 长度为 0，视为接收成功
        if (len == 0)
        {
            return true;
        }

        if (buffer == nullptr)
        {
            return false;
        }

        std::size_t totalReceived = 0;

        while (totalReceived < len)
        {
            // =====================================================
            // recv() 一次不保证拿到完整目标长度，所以必须循环收满。
            // 这和实验文档里 TotalRecv() 的设计思想一致。
            // =====================================================
            ssize_t received = ::recv(sockfd,
                                      buffer + totalReceived,
                                      len - totalReceived,
                                      0);

            if (received > 0)
            {
                totalReceived += static_cast<std::size_t>(received);
                continue;
            }

            // received == 0 表示对端已关闭连接
            if (received == 0)
            {
                return false;
            }

            // 被信号中断则重试
            if (errno == EINTR)
            {
                continue;
            }

            // 其他错误
            return false;
        }

        return true;
    }

    bool sendPacket(int sockfd, const std::vector<unsigned char>& packet)
    {
        // =========================================================
        // 消息包格式：
        // [4 字节长度头][实际数据体]
        //
        // 长度头用网络字节序发送，保证不同主机字节序一致。
        // =========================================================

        if (packet.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
        {
            return false;
        }

        std::uint32_t bodyLength = static_cast<std::uint32_t>(packet.size());
        std::uint32_t networkLength = hostToNetwork32(bodyLength);

        unsigned char header[LENGTH_HEADER_SIZE];
        std::memcpy(header, &networkLength, LENGTH_HEADER_SIZE);

        // 先发长度头
        if (!sendAll(sockfd, header, LENGTH_HEADER_SIZE))
        {
            return false;
        }

        // 再发包体
        if (!packet.empty())
        {
            if (!sendAll(sockfd, packet.data(), packet.size()))
            {
                return false;
            }
        }

        return true;
    }

    bool recvPacket(int sockfd, std::vector<unsigned char>& packet)
    {
        packet.clear();

        // =========================================================
        // 第一步：接收 4 字节长度头
        // =========================================================
        unsigned char header[LENGTH_HEADER_SIZE] = {0};
        if (!recvAll(sockfd, header, LENGTH_HEADER_SIZE))
        {
            return false;
        }

        std::uint32_t networkLength = 0;
        std::memcpy(&networkLength, header, LENGTH_HEADER_SIZE);

        std::uint32_t bodyLength = networkToHost32(networkLength);

        // 长度为 0 的包，允许存在，直接返回空包
        if (bodyLength == 0)
        {
            return true;
        }

        // =========================================================
        // 第二步：按长度接收完整包体
        // =========================================================
        packet.resize(bodyLength);
        if (!recvAll(sockfd, packet.data(), packet.size()))
        {
            packet.clear();
            return false;
        }

        return true;
    }

    void closeSocket(int sockfd)
    {
        if (sockfd >= 0)
        {
            ::close(sockfd);
        }
    }

} // namespace secure_chat
