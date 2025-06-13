#!/bin/bash
# install GitHub Command
(type -p wget >/dev/null || (sudo apt update && sudo apt-get install wget -y)) \
	&& sudo mkdir -p -m 755 /etc/apt/keyrings \
        && out=$(mktemp) && wget -nv -O$out https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        && cat $out | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
	&& sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
	&& echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
	&& sudo apt update \
	&& sudo apt install gh -y

# AppImage needs FUSE to run
sudo apt-get install fuse libfuse2

export GO_VERSION="1.24.4"
wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz


git config --global user.name "hp"
git config --global user.email "hpdevelop@users.noreply.github.com"

echo 'export GOROOT=/usr/local/go' | sudo tee -a /etc/profile.d/go.sh
echo 'export GOPATH=$HOME/go' | sudo tee -a /etc/profile.d/go.sh
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' | sudo tee -a /etc/profile.d/go.sh
source /etc/profile.d/go.sh

go install sigs.k8s.io/kind@v0.27.0
echo "run kind create cluster to start a local k8s with kind"

echo "gh auth login"
echo "gh auth setup-git"
echo "gh repo clone superplayground3000/goscant"