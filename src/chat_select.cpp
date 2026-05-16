#include "chat_select.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "chat.h"
#include "tcp.h"
#include "utils.h"

namespace secure_chat
{
    void secretChatSelect(int sockfd,
                          const std::string& peerName,
                          const std::string& key,
                          AlgorithmType algorithmType)
    {
        std::cout << "[CHAT] select model enabled.\n";
        std::cout << "[CHAT] Type message and press Enter. Type quit to exit.\n";

        while (true)
        {
            // 1. 初始化 fd_set，将标准输入和 socket 都加入监听集合。
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(STDIN_FILENO, &readfds);
            FD_SET(sockfd, &readfds);

            const int maxFd = std::max(STDIN_FILENO, sockfd);

            // 2. 使用 select 阻塞等待任意一个描述符变为可读。
            const int ret = ::select(maxFd + 1, &readfds, nullptr, nullptr, nullptr);

            if (ret < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }

                throw std::runtime_error(
                    std::string("select() failed: ") + std::strerror(errno)
                );
            }

            // 3. 若 socket 可读，说明对端发来了密文包。
            if (FD_ISSET(sockfd, &readfds))
            {
                std::vector<unsigned char> cipherPacket;

                if (!recvPacket(sockfd, cipherPacket))
                {
                    std::cout << "[INFO] Peer disconnected or receive failed. Chat ended.\n";
                    break;
                }

                std::string plainText =
                    decryptMessage(cipherPacket, key, algorithmType);

                plainText = trimNewline(plainText);

                if (!plainText.empty())
                {
                    std::cout << "Receive message form <" << peerName << ">: "
                              << plainText << "\n";
                }

                if (isQuitCommand(plainText))
                {
                    std::cout << "Quit!\n";
                    break;
                }
            }

            // 4. 若标准输入可读，说明用户输入了待发送明文。
            if (FD_ISSET(STDIN_FILENO, &readfds))
            {
                std::string inputLine;

                if (!std::getline(std::cin, inputLine))
                {
                    std::cout << "[INFO] Standard input closed. Stop chatting.\n";
                    break;
                }

                inputLine = trimNewline(inputLine);

                if (inputLine.empty())
                {
                    continue;
                }

                std::vector<unsigned char> cipherPacket =
                    encryptMessage(inputLine, key, algorithmType);

                if (!sendPacket(sockfd, cipherPacket))
                {
                    std::cerr << "[ERROR] sendPacket() failed.\n";
                    break;
                }

                if (isQuitCommand(inputLine))
                {
                    std::cout << "Quit!\n";
                    break;
                }
            }
        }

        // 5. 聊天结束后关闭双向通信，通知对端退出。
        if (sockfd >= 0)
        {
            ::shutdown(sockfd, SHUT_RDWR);
        }
    }

} // namespace secure_chat
