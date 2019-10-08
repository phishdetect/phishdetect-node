.DEFAULT_GOAL = linux
BUILD_FOLDER  = $(shell pwd)/build
FLAGS_LINUX   = GOOS=linux GOARCH=amd64 CGO_ENABLED=1

lint:
	@echo "[lint] Running linter on codebase"
	@golint ./...

deps:
	@echo "[deps] Downloading modules..."
	go mod download
	go get -u github.com/gobuffalo/packr/...

	@echo "[deps] Done!"

linux:
	@mkdir -p $(BUILD_FOLDER)/linux

	@echo "[builder] Building PhishDetect Node Linux executable"
	$(FLAGS_LINUX) packr build -o $(BUILD_FOLDER)/linux/phishdetect-node

	@echo "[builder] Done!"

clean:
	rm -rf $(BUILD_FOLDER)
