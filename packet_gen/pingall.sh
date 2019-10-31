#!/bin/bash
set -x
for i in {0..9}
do
  while read line;
  do
    ip=`echo $line | awk '{print $1}'`
    if [ $ip != "127.0.0.1" ];
    then
      host=`hostname`
      nping -c 1 --udp -p 9090 --data-string "This is UDP message $i from $host to $ip" -v-3 $ip
      nping -c 1 --icmp $ip
    fi
  done < /etc/hosts
done
