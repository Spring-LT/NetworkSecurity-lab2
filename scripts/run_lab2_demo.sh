#!/usr/bin/env bash

set -e

PORT="${1:-9004}"

echo "============================================="
echo " Lab2 RSA-DES Demo Helper"
echo "============================================="
echo "Port: ${PORT}"
echo
echo "请打开两个终端："
echo
echo "终端 A 运行服务端："
echo "  ./bin/rsa_chat -m server -p ${PORT} --io select"
echo
echo "终端 B 运行客户端："
echo "  ./bin/rsa_chat -m client -i 127.0.0.1 -p ${PORT} --io select"
echo
echo "建议测试消息："
echo "  hello"
echo "  Network Security Lab2"
echo "  RSA distributes DES key automatically"
echo "  quit"
echo
echo "如需抓包验证："
echo "  sudo tcpdump -i lo -nn -s 0 -X 'tcp port ${PORT}'"
echo "============================================="
