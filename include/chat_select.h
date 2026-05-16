#pragma once

#include <string>

#include "config.h"

namespace secure_chat
{
    /**
     * @brief 使用 select 实现单进程全双工聊天
     *
     * 与第一次实验 fork 版本相比：
     * 1. 不创建父子进程。
     * 2. 同时监听标准输入和 socket。
     * 3. 当键盘可读时发送消息，当 socket 可读时接收消息。
     */
    void secretChatSelect(int sockfd,
                          const std::string& peerName,
                          const std::string& key,
                          AlgorithmType algorithmType);

} // namespace secure_chat
