.DEFAULT_GOAL = build

BUILD_FOLDER  = $(shell pwd)/build
FLAGS_LINUX   = GOOS=linux GOARCH=amd64 CGO_ENABLED=1

YARA_VERSION ?= 4.0.1
YARA_SRC = /tmp/yara-$(YARA_VERSION)
YARA_TAR = $(YARA_SRC).tar.gz

.PHONY: yara
yara:
	wget https://github.com/VirusTotal/yara/archive/v$(YARA_VERSION).tar.gz -O $(YARA_TAR)
	tar -C /tmp -xzf $(YARA_TAR)
	cd $(YARA_SRC) && ./bootstrap.sh && ./configure && make
	cd $(YARA_SRC) && sudo make install
	sudo ldconfig

.PHONY: pre
pre: clean
	@mkdir -p $(BUILD_FOLDER)
	env GO111MODULE=on go get -d ./
	env GO111MODULE=on go mod download
	env GO111MODULE=on go mod tidy

.PHONY: build
build: pre
	@echo "[builder] Building PhishDetect Node executable"
	$(FLAGS_LINUX) go build -o $(BUILD_FOLDER)/phishdetect-node
	@echo "[builder] Done!"

.PHONY: lint
lint:
	@echo "[lint] Running linter on codebase"
	@golint ./...

.PHONY: fmt
fmt:
	@echo "[gofmt] Formatting code"
	gofmt -s -w .

.PHONY: clean
clean:
	rm -rf $(BUILD_FOLDER)
