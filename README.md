# Derpcipher

Simple private key encryption tool for small files. It uses Golang version of NaCL SecretBox.
Basic structure of the CLI is a shameless copy from [dep](https://github.com/golang/dep) tool `:3`

### Installation

	go get github.com/adrpino/derpcipher

### Usage
Interactive (asks for text and password)


	derp cipher



### TODO
- Implement `decipher` command
- Reading and writing to files
- Read pass from environment pass
