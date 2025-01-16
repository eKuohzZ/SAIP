#!/bin/bash

# 定义CSV文件的路径
CSV_FILE="port_list.csv"

# 检查CSV文件是否存在
if [ ! -f "$CSV_FILE" ]; then
  echo "CSV file '$CSV_FILE' not found. Please create the file and add port numbers."
  exit 1
fi

# 清除已存在的出方向规则，以确保不会重复添加
iptables -F OUTPUT

# 从CSV文件中读取端口号并添加出方向RST拦截规则
while IFS=, read -r port
do
  if [ -n "$port" ]; then
    iptables -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP
    echo "Added rule to drop RST packets on port $port"
  fi
done < "$CSV_FILE"

# 保存iptables规则以便重启后生效
# 根据你的Linux发行版，使用适当的命令保存iptables规则
# CentOS/Red Hat
service iptables save

# Debian/Ubuntu
# iptables-save > /etc/iptables/rules.v4

echo "Rules have been added to drop RST packets on the specified ports."
