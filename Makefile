BINARY_NAME=ssh2iterm2

build:
	go build -o ${BINARY_NAME} ${BINARY_NAME}.go

clean:
	go clean