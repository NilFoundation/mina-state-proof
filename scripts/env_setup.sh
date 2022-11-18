#!/bin/bash
# Install ganache
apt install nodejs
apt install npm
npm install -g ganache

# Run ganache on port 8545
ganache -l 100000000000 --miner.callGasLimit 100000000000 -p 8545

# Check latest Mina-Berkeley release https://github.com/MinaProtocol/mina/discussions/12217
# Download the latest release and run node

# First, set up and update the unstable Debian Repository for your platform. Replace the word CODENAME with the appropriate codename for your machine, one of bionic, focal, stretch, buster, or bullseye and run:
CODENAME=focal
echo "deb [trusted=yes] http://packages.o1test.net/ CODENAME unstable" | tee /etc/apt/sources.list.d/mina-unstable.list
apt-get update
apt-get install -y mina-berkeley=1.3.2beta2-release-2.0.0-0b63498
mina libp2p generate-keypair -privkey-path /root/mina_keys
mina daemon --peer-list-url https://storage.googleapis.com/seed-lists/berkeley_seeds.txt --libp2p-keypair /root/mina_keys