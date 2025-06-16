#!/bin/bash

set -e

APP_NAME="goscant"
LINUX_BIN="${APP_NAME}_linux_amd64"
WIN_BIN="${APP_NAME}_windows.exe"
DOCKER_IMAGE="goscant:latest"

usage() {
  echo "Usage: $0 [binaries|docker]"
  echo "  binaries   Build Linux amd64 and Windows executables."
  echo "  docker     Build a Docker image using Ubuntu 22.04."
  exit 1
}

if [ $# -ne 1 ]; then
  usage
fi

case "$1" in
  binaries)
    echo "Building Linux amd64 binary..."
    GOOS=linux GOARCH=amd64 go build -o "$LINUX_BIN" main.go
    echo "Building Windows amd64 binary..."
    GOOS=windows GOARCH=amd64 go build -o "$WIN_BIN" main.go
    echo "Binaries built: $LINUX_BIN, $WIN_BIN"
    ;;
  docker)
    echo "Building Docker image..."
    docker build -t "$DOCKER_IMAGE" -f Dockerfile .
    echo "Docker image built: $DOCKER_IMAGE"
    ;;
  *)
    usage
    ;;
esac 