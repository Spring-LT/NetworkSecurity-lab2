#pragma once

#include <string>

namespace secure_chat
{
    /**
     * @brief 聊天 IO 模型
     *
     * FORK：复用第一次实验父子进程全双工模型。
     * SELECT：实验二扩展，实现单进程 select 全双工模型。
     */
    enum class ChatIoModel
    {
        FORK = 1,
        SELECT = 2
    };

    /**
     * @brief 实验二服务端主流程
     */
    void runRsaDesServer(int port, ChatIoModel ioModel);

    /**
     * @brief 实验二客户端主流程
     */
    void runRsaDesClient(const std::string& serverIp,
                         int port,
                         ChatIoModel ioModel);

    /**
     * @brief 解析 IO 模型字符串
     */
    bool parseChatIoModel(const std::string& text, ChatIoModel& model);

    /**
     * @brief IO 模型转字符串
     */
    std::string chatIoModelToString(ChatIoModel model);

} // namespace secure_chat
