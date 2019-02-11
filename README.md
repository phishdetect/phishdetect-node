# PhishDetect Node

This software is part of the PhishDetect project.

This is the server component of PhishDetect, normally referred to as PhishDetect Node. It is what performs the requested analysis of suspicious links and web pages, and that offers a REST API the PhishDetect Browser Extension (as well as other clients) communicates with in order to pull malicious indicators and to push alerts.


## Build

In order to build PhishDetect Node you need Go 1.11+ installed. You can then proceed with:

    make deps
    make linux

For proper documentation please refer to the [Admin Guide](https://phishdetect.gitbook.io/admin-guide/).


## License

PhishDetect Node is released under GNU Affero General Public License 3.0 and is copyrighted to Claudio Guarnieri.

The hook icon was created by Alex Fuller from Noun Project.
