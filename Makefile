.PHONY: build clean default test

build: clean
	@go build -o ./bin/machineid ./cmd/machineid/main.go

clean:
	@rm -rf ./machineid

test:
	go test ./...

default: build
