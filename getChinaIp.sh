#!/bin/bash
#variables,定义用到的变量

ip_txt_path=./china_ip.txt;
ip_url='http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest';

#mv old txt,每次下载前把旧的ip地址文件改名，删除也可以

cur_time=$(date +"%Y%m%d%H%M%S");
if [ -f ${ip_txt_path} ];then
       mv ${ip_txt_path} ${ip_txt_path}_${cur_time};
fi

#download 用curl下载，保存到我们所定义的文本文件中

curl ${ip_url} | grep ipv4 | grep CN | awk -F\| '{ printf("%s/%d\n", $4, 32-log($5)/log(2)) }' >${ip_txt_path}

#parse 2 redis,用php脚本解析，保存到redis

echo "begin parse ip\n";
