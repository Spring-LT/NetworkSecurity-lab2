#include "chat.h"

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "des.h"
#include "aes.h"
#include "tdes.h"
#include "tcp.h"
#include "utils.h"

namespace secure_chat
{
    namespace
    {
        /**
         * @brief 尝试结束子进程，避免父进程退出后留下孤儿/僵尸进程
         *
         * 说明：
         * 聊天中使用 fork() 实现全双工：
         * - 父进程负责收
         * - 子进程负责发
         *
         * 当父进程因“对端退出”或“连接断开”结束时，子进程可能仍阻塞在标准输入上，
         * 此时需要主动结束子进程。
         */
        void terminateChildProcess(pid_t childPid)
        {
            if (childPid <= 0)
            {
                return;
            }

            // 先发送 SIGTERM 请求优雅结束
            ::kill(childPid, SIGTERM);

            // 回收子进程，避免僵尸进程
            int status = 0;
            ::waitpid(childPid, &status, 0);
        }

        /**
         * @brief 校验算法类型是否为本程序已实现的分支
         *
         * 说明：
         * - 本项目已实现 DES / 3DES(EDE) / AES-128
         * - 该检查用于尽早发现“未识别/未实现的算法枚举值”
         */
        void ensureAlgorithmSupportedInCurrentPhase(AlgorithmType algorithmType)
        {
            switch (algorithmType)
            {
                case AlgorithmType::DES:
                case AlgorithmType::TDES:
                case AlgorithmType::AES128:
                    // 已实现：DES / 3DES / AES-128
                    return;

                default:
                    throw std::runtime_error("未知算法类型。");
            }
        }

        /**
         * @brief 关闭 socket 的写方向
         *
         * 说明：
         * 当本地发送结束时，只关闭写方向比直接 close 更温和：
         * - 告诉对端“我不会再发数据了”
         * - 但仍然允许继续接收对端数据
         *
         * 这与实验文档中对 shutdown() 的说明一致。
         */
        void shutdownWriteSide(int sockfd)
        {
            if (sockfd >= 0)
            {
                ::shutdown(sockfd, SHUT_WR);
            }
        }

        /**
         * @brief 关闭 socket 的双向通信
         */
        void shutdownBothSides(int sockfd)
        {
            if (sockfd >= 0)
            {
                ::shutdown(sockfd, SHUT_RDWR);
            }
        }

    } // namespace

    void runServer(int port, const std::string& key, AlgorithmType algorithmType)
    {
        // 先校验算法类型是否为已实现分支
        ensureAlgorithmSupportedInCurrentPhase(algorithmType);

        // 再做一次密钥合法性检查（main.cpp 中虽然已检查过，这里再兜底一次更稳）
        std::string reason;
        if (!validateKeyForAlgorithm(key, algorithmType, &reason))
        {
            throw std::runtime_error("服务端启动失败，密钥非法: " + reason);
        }

        // =========================================================
        // 1. 创建监听 socket
        // 2. 输出监听信息
        // 3. accept() 等待客户端
        // 4. 连接建立后进入聊天
        // =========================================================
        int listenFd = -1;
        int connFd = -1;

        try
        {
            listenFd = createServerSocket(port);

            std::cout << "Listening on port " << port << " ...\n";

            std::string clientIp;
            int clientPort = 0;

            connFd = acceptClient(listenFd, clientIp, clientPort);

            // 与实验文档示例一致：连接建立后可关闭监听 socket
            closeSocket(listenFd);
            listenFd = -1;

            std::cout << "server: got connection from "
                      << clientIp
                      << ", port "
                      << clientPort
                      << ", socket "
                      << connFd
                      << "\n";

            secretChat(connFd, clientIp, key, algorithmType);

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

    void runClient(const std::string& serverIp,
                   int port,
                   const std::string& key,
                   AlgorithmType algorithmType)
    {
        // 先校验算法类型是否为已实现分支
        ensureAlgorithmSupportedInCurrentPhase(algorithmType);

        // 再做一次密钥合法性检查
        std::string reason;
        if (!validateKeyForAlgorithm(key, algorithmType, &reason))
        {
            throw std::runtime_error("客户端启动失败，密钥非法: " + reason);
        }

        int sockfd = -1;

        try
        {
            sockfd = createClientSocket(serverIp, port);

            std::cout << "Connect Success!\n";
            std::cout << "Begin to chat...\n";

            secretChat(sockfd, serverIp, key, algorithmType);

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

    void secretChat(int sockfd,
                    const std::string& peerName,
                    const std::string& key,
                    AlgorithmType algorithmType)
    {
        // =========================================================
        // 按实验文档思路，用 fork() 实现全双工聊天：
        //
        // 父进程：
        //   不断从 socket 收消息 -> 解密 -> 输出
        //
        // 子进程：
        //   不断从标准输入读取 -> 加密 -> 发送
        //
        // 这样父子进程并发运行，就能实现“边发边收”的全双工聊天。
        // =========================================================
        pid_t pid = ::fork();

        if (pid < 0)
        {
            throw std::runtime_error("fork() failed");
        }

        if (pid == 0)
        {
            // =====================================================
            // 子进程：负责发送
            // =====================================================
            try
            {
                chatSendLoop(sockfd, key, algorithmType);
            }
            catch (const std::exception& ex)
            {
                std::cerr << "[ERROR] 发送进程异常: " << ex.what() << "\n";
            }
            catch (...)
            {
                std::cerr << "[ERROR] 发送进程发生未知异常。\n";
            }

            // 子进程结束前，关闭写方向，通知对端本端不再发送
            shutdownWriteSide(sockfd);

            // 子进程直接退出，避免继续向下执行父进程路径
            ::_exit(0);
        }
        else
        {
            // =====================================================
            // 父进程：负责接收
            // =====================================================
            try
            {
                chatReceiveLoop(sockfd, peerName, key, algorithmType);
            }
            catch (const std::exception& ex)
            {
                std::cerr << "[ERROR] 接收进程异常: " << ex.what() << "\n";
            }
            catch (...)
            {
                std::cerr << "[ERROR] 接收进程发生未知异常。\n";
            }

            // 父进程接收结束，说明聊天应整体结束：
            // 1. 关闭双向连接
            // 2. 结束子进程
            shutdownBothSides(sockfd);
            terminateChildProcess(pid);
        }
    }

    void chatReceiveLoop(int sockfd,
                         const std::string& peerName,
                         const std::string& key,
                         AlgorithmType algorithmType)
    {
        while (true)
        {
            // =====================================================
            // 从 socket 接收一个完整密文包
            // recvPacket() 内部会先收长度头，再收包体
            // =====================================================
            std::vector<unsigned char> cipherPacket;
            bool ok = recvPacket(sockfd, cipherPacket);

            // 对端关闭或接收失败
            if (!ok)
            {
                std::cout << "[INFO] Peer disconnected or receive failed. Chat ended.\n";
                break;
            }

            // 解密得到明文
            std::string plainText = decryptMessage(cipherPacket, key, algorithmType);

            // 出于稳健性考虑，做一下尾部换行清理
            plainText = trimNewline(plainText);

            // 空消息直接忽略
            if (plainText.empty())
            {
                continue;
            }

            std::cout << "Receive message form <" << peerName << ">: "
                      << plainText
                      << "\n";

            // 若对方发送 quit，则结束本地接收循环
            if (isQuitCommand(plainText))
            {
                std::cout << "Quit!\n";
                break;
            }
        }
    }

    void chatSendLoop(int sockfd,
                      const std::string& key,
                      AlgorithmType algorithmType)
    {
        while (true)
        {
            // =====================================================
            // 从标准输入读取一行待发送内容
            //
            // 与旧版 fgets() 思路类似，但这里用 C++ 的 getline()，
            // 可读性更好，也更利于与 std::string 配合。
            // =====================================================
            std::string inputLine;
            if (!std::getline(std::cin, inputLine))
            {
                // 例如用户输入了 Ctrl+D，视为本地输入结束
                std::cout << "[INFO] Standard input closed. Stop sending.\n";
                break;
            }

            inputLine = trimNewline(inputLine);

            // 可根据需要决定是否忽略空消息
            if (inputLine.empty())
            {
                continue;
            }

            // 加密消息
            std::vector<unsigned char> cipherPacket =
                encryptMessage(inputLine, key, algorithmType);

            // 发送密文包
            bool ok = sendPacket(sockfd, cipherPacket);
            if (!ok)
            {
                std::cerr << "[ERROR] sendPacket() failed.\n";
                break;
            }

            // 若本地输入 quit，则发送后结束发送循环
            if (isQuitCommand(inputLine))
            {
                std::cout << "Quit!\n";
                break;
            }
        }
    }

    std::vector<unsigned char> encryptMessage(const std::string& message,
                                              const std::string& key,
                                              AlgorithmType algorithmType)
    {
        switch (algorithmType)
        {
            case AlgorithmType::DES:
            {
                // DES 分支
                DES des;
                if (!des.setKey(key))
                {
                    throw std::runtime_error("DES setKey() failed: invalid key");
                }

                // 将字符串转为字节数组后进行加密
                std::vector<unsigned char> plainBytes = stringToBytes(message);
                std::vector<unsigned char> cipherBytes = des.encrypt(plainBytes);

                if (cipherBytes.empty() && !plainBytes.empty())
                {
                    throw std::runtime_error("DES encrypt() failed");
                }

                return cipherBytes;
            }

            case AlgorithmType::TDES:
            {
                TripleDES tdes;
                if (!tdes.setKey(key))
                {
                    throw std::runtime_error("3DES setKey() failed: invalid key format");
                }

                std::vector<unsigned char> plainBytes = stringToBytes(message);
                std::vector<unsigned char> cipherBytes = tdes.encrypt(plainBytes);

                if (cipherBytes.empty())
                {
                    throw std::runtime_error("3DES encrypt() failed");
                }

                return cipherBytes;
            }

            case AlgorithmType::AES128:
            {
                AES128 aes;
                if (!aes.setKey(key))
                {
                    throw std::runtime_error("AES-128 setKey() failed: invalid key");
                }

                std::vector<unsigned char> plainBytes = stringToBytes(message);
                std::vector<unsigned char> cipherBytes = aes.encrypt(plainBytes);

                if (cipherBytes.empty())
                {
                    throw std::runtime_error("AES-128 encrypt() failed");
                }

                return cipherBytes;
            }

            default:
                throw std::runtime_error("Unknown algorithm type in encryptMessage()");
        }
    }

    std::string decryptMessage(const std::vector<unsigned char>& cipher,
                               const std::string& key,
                               AlgorithmType algorithmType)
    {
        switch (algorithmType)
        {
            case AlgorithmType::DES:
            {
                // DES 分支
                DES des;
                if (!des.setKey(key))
                {
                    throw std::runtime_error("DES setKey() failed: invalid key");
                }

                std::vector<unsigned char> plainBytes = des.decrypt(cipher);

                // 密文非空但解密结果异常为空，这里视为错误
                if (cipher.size() > 0 && plainBytes.empty())
                {
                    throw std::runtime_error("DES decrypt() failed");
                }

                return bytesToString(plainBytes);
            }

            case AlgorithmType::TDES:
            {
                TripleDES tdes;
                if (!tdes.setKey(key))
                {
                    throw std::runtime_error("3DES setKey() failed: invalid key format");
                }

                std::vector<unsigned char> plainBytes = tdes.decrypt(cipher);
                if (cipher.size() > 0 && plainBytes.empty())
                {
                    throw std::runtime_error("3DES decrypt() failed");
                }

                return bytesToString(plainBytes);
            }

            case AlgorithmType::AES128:
            {
                AES128 aes;
                if (!aes.setKey(key))
                {
                    throw std::runtime_error("AES-128 setKey() failed: invalid key");
                }

                std::vector<unsigned char> plainBytes = aes.decrypt(cipher);
                if (cipher.size() > 0 && plainBytes.empty())
                {
                    throw std::runtime_error("AES-128 decrypt() failed");
                }

                return bytesToString(plainBytes);
            }

            default:
                throw std::runtime_error("Unknown algorithm type in decryptMessage()");
        }
    }

} // namespace secure_chat
