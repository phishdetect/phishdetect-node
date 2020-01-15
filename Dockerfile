FROM golang:1.13

WORKDIR /go/src/app
COPY . .

RUN apt-get update -y && apt-get install -y libyara-dev pkg-config

RUN make deps
RUN make linux

ENTRYPOINT ./build/linux/phishdetect-node --host 0.0.0.0
