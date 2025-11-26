BINARY_NAME=ssh2iterm2

all: build install clean

build:
	go build -o ${BINARY_NAME} *.go

intel:
	GOOS=darwin GOARCH=amd64 go build -o ${BINARY_NAME}-amd64 *.go

m1:
	GOOS=darwin GOARCH=arm64 go build -o ${BINARY_NAME}-arm64 *.go

clean:
	go clean

install:
	cp ${BINARY_NAME} ~/.local/bin/
	chmod +x ~/.local/bin/${BINARY_NAME}

