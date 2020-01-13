[![Build Status](https://api.travis-ci.org/phishdetect/phishdetect-node.png?branch=master)](https://travis-ci.org/phishdetect/phishdetect-node)
[![Go Report Card][goreportcard-badge]][goreportcard]

# PhishDetect Node

This software is part of the PhishDetect project.

This is the server component of PhishDetect, normally referred to as PhishDetect Node. It is what performs the requested analysis of suspicious links and web pages, and that offers a REST API the PhishDetect Browser Extension (as well as other clients) communicates with in order to pull malicious indicators and to push alerts.

## Install

In order to run PhishDetect Node you only need to download the `phishdetect-node` binary from the [latest release](https://github.com/phishdetect/phishdetect-node/releases/latest).

## Build

In order to build PhishDetect Node you need Go 1.12+ installed. You can then proceed with:

    make deps
    make linux

For proper documentation please refer to the [Admin Guide](https://phishdetect.gitbook.io/admin-guide/).

## Docker

To build and run PhishDetect Node in a local Docker container, install Docker
and run

    docker build -t phishdetect-node .
    docker run -it --rm --name phishdetect-container -p 7856:7856 phishdetect-node

You can then access the node at `localhost:7856`.

## License

PhishDetect Node is released under GNU Affero General Public License 3.0 and is copyrighted to Claudio Guarnieri.

The hook icon was created by Alex Fuller from Noun Project.

[goreportcard]: https://goreportcard.com/report/github.com/phishdetect/phishdetect-node
[goreportcard-badge]: https://goreportcard.com/badge/github.com/phishdetect/phishdetect-node
