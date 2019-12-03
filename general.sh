#!/bin/bash
set -x
sudo apt-get -y update
sudo apt-get -y install nmap
sudo ufw allow 9090
sudo ufw allow 9999
#wget https://repo.anaconda.com/archive/Anaconda3-5.3.0-Linux-x86_64.sh
#sudo bash -c "bash Anaconda3-5.3.0-Linux-x86_64.sh -b -p /opt/anaconda3"
#sudo bash -c "echo 'ANACONDA_HOME=/opt/anaconda3/' >> /etc/profile"
#sudo bash -c "echo 'PATH=/opt/anaconda3/bin:$PATH' >> /etc/profile"

sudo apt-get install -y netwox
sudo apt-get install -y xinetd telnetd tcpd
sudo bash -c "echo 'telnet stream tcp nowait telnetd /usr/sbin/tcpd /usr/sbin/in.telnetd' >> /etc/inetd.conf"
sudo /etc/init.d/xinetd restart

sudo DEBIAN_FRONTEND=noninteractive apt-get install -q -y tshark

sudo ip link set eth0 promisc on
#sudo ip link set eth1 promisc on

sudo useradd -m -s /bin/bash seed
sudo echo "seed:dees" | chpasswd
sudo usermod -a -G sudo seed
