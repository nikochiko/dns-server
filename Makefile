.PHONY: build
build:
	GOOS=darwin GOARCH=arm64 go build -o dns-server_arm64 # M1 mac
	GOOS=linux GOARCH=amd64 go build -o dns-server_amd64 # x64 linux
