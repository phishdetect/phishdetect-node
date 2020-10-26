.DEFAULT_GOAL = build
BUILD_FOLDER  = $(shell pwd)/build
FLAGS_LINUX   = GOOS=linux GOARCH=amd64 CGO_ENABLED=1

clean:
	rm -rf $(BUILD_FOLDER)

pre: clean
	@mkdir -p $(BUILD_FOLDER)
	env GO111MODULE=on go get -d ./
	env GO111MODULE=on go mod download
	go get -u github.com/gobuffalo/packr/...
	env GO111MODULE=on go mod tidy

build: pre
	@echo "[builder] Building PhishDetect Node executable"
	$(FLAGS_LINUX) packr build -o $(BUILD_FOLDER)/phishdetect-node
	@echo "[builder] Done!"

lint:
	@echo "[lint] Running linter on codebase"
	@golint ./...

fmt:
	@echo "[gofmt] Formatting code"
	gofmt -s -w .
