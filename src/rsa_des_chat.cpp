#include "rsa_des_chat.h"

#include <iostream>
#include <stdexcept>

#include "chat.h"
#include "chat_select.h"
#include "config.h"
#include "key_exchange.h"
#include "tcp.h"
#include "utils.h"

namespace secure_chat
{
    bool parseChatIoModel(const std::string& text, ChatIoModel& model)
    {
        const std::string lower = toLower(trim(text));

        if (lower == "fork" || lower == "f" || lower == "1")
        {
            model = ChatIoModel::FORK;
            return true;
        }

        if (lower == "select" || lower == "s" || lower == "2")
        {
            model = ChatIoModel::SELECT;
            return true;
        }

        return false;
    }

    std::string chatIoModelToString(ChatIoModel model)
    {
        switch (model)
        {
            case ChatIoModel::FORK:
                return "fork";

            case ChatIoModel::SELECT:
                return "select";

            default:
                return "unknown";
        }
    }

    void runRsaDesServer(int port, ChatIoModel ioModel)
    {
        int listenFd = -1;
        int connFd = -1;

        try
        {
            // 1. 创建服务端监听 socket。
            listenFd = createServerSocket(port);

            std::cout << "[TCP] Listening on port " << port << " ...\n";

            // 2. 等待客户端连接。
            std::string clientIp;
            int clientPort = 0;

            connFd = acceptClient(listenFd, clientIp, clientPort);

            closeSocket(listenFd);
            listenFd = -1;

            std::cout << "[TCP] Client connected from "
                      << clientIp << ":" << clientPort << "\n";

            // 3. 执行 RSA-DES 自动密钥交换。
            std::cout << "[RSA] Start RSA-DES key exchange as server.\n";
            const std::string desKey = serverPerformRsaDesKeyExchange(connFd);

            // 4. 使用协商得到的 DES 会话密钥进入加密聊天。
            std::cout << "[CHAT] Begin DES encrypted chat.\n";

            if (ioModel == ChatIoModel::SELECT)
            {
                secretChatSelect(connFd, clientIp, desKey, AlgorithmType::DES);
            }
            else
            {
                secretChat(connFd, clientIp, desKey, AlgorithmType::DES);
            }

            // 5. 关闭通信 socket。
            closeSocket(connFd);
            connFd = -1;
        }
        catch (...)
        {
            if (connFd >= 0)
            {
                closeSocket(connFd);
            }

            if (listenFd >= 0)
            {
                closeSocket(listenFd);
            }

            throw;
        }
    }

    void runRsaDesClient(const std::string& serverIp,
                         int port,
                         ChatIoModel ioModel)
    {
        int sockfd = -1;

        try
        {
            // 1. 客户端连接服务端。
            sockfd = createClientSocket(serverIp, port);

            std::cout << "[TCP] Connect Success.\n";

            // 2. 执行 RSA-DES 自动密钥交换。
            std::cout << "[RSA] Start RSA-DES key exchange as client.\n";
            const std::string desKey = clientPerformRsaDesKeyExchange(sockfd);

            // 3. 使用客户端自动生成的 DES 会话密钥进入加密聊天。
            std::cout << "[CHAT] Begin DES encrypted chat.\n";

            if (ioModel == ChatIoModel::SELECT)
            {
                secretChatSelect(sockfd, serverIp, desKey, AlgorithmType::DES);
            }
            else
            {
                secretChat(sockfd, serverIp, desKey, AlgorithmType::DES);
            }

            // 4. 关闭 socket。
            closeSocket(sockfd);
            sockfd = -1;
        }
        catch (...)
        {
            if (sockfd >= 0)
            {
                closeSocket(sockfd);
            }

            throw;
        }
    }

} // namespace secure_chat
