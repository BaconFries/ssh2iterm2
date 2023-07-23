BINARY_NAME=ssh2iterm2

all: build install clean

build:
	go build -o ${BINARY_NAME} *.go

clean:
	go clean

install:
	cp ${BINARY_NAME} /usr/local/bin/
	chmod +x /usr/local/bin/${BINARY_NAME}