#!/bin/sh
# Сборка всех бинарников в ./dist (нужен Go >= 1.22, интернет не нужен).
set -e
cd "$(dirname "$0")"
go test ./...
mkdir -p dist
export CGO_ENABLED=0
GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/mschapv3-server-linux-amd64        ./cmd/server
GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/mschapv3-server-linux-arm64        ./cmd/server
GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/mschapv3-client-termux-arm64       ./cmd/client-termux
GOOS=linux   GOARCH=arm   go build -trimpath -ldflags="-s -w" -o dist/mschapv3-client-termux-arm         ./cmd/client-termux
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/mschapv3-client-windows-amd64.exe  ./cmd/client-windows
GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/mschapv3-client-windows-arm64.exe  ./cmd/client-windows
ls -l dist
