<p align="center">
     <img src="https://raw.githubusercontent.com/phishdetect/assets/main/logos/phishdetect.png" width="300" />
     <p align="center">
          <a href="https://travis-ci.org/phishdetect/phishdetect-node"><img src="https://api.travis-ci.org/phishdetect/phishdetect-node.png?branch=master" alt="Build Status" /></a>
          <a href="https://goreportcard.com/report/github.com/phishdetect/phishdetect-node"><img src="https://goreportcard.com/badge/github.com/phishdetect/phishdetect-node" alt="Report Card" /></a>
     </p>
</p>

# PhishDetect Node

This software is part of the PhishDetect project.

This is the server component of PhishDetect, normally referred to as PhishDetect Node. It is what performs the requested analysis of suspicious links and web pages, and that offers a REST API the PhishDetect Browser Extension (as well as other clients) communicates with in order to pull malicious indicators and to push alerts.

## Install

PhishDetect Node requires Yara to execute. Yara is optionally used in case you want to provide the server the ability to scan suspicious pages with a set of Yara rules. It is preferable that you compile it from sources, please refer to the [official documentation](https://yara.readthedocs.io/en/stable/).

In order to run PhishDetect Node you only need to download the `phishdetect-node` binary from the [latest release](https://github.com/phishdetect/phishdetect-node/releases/latest). You can simply launch the binary for a default configuration, or explore all of the available command-line options:

     Usage of phishdetect-node:
           --api-version string    Specify which Docker API version to use (default "1.37")
           --brands string         Specify a folder containing YAML files with Brand specifications
           --contacts string       Specify a link to information or contacts details to be provided to your users
           --create-user           Create a new user
           --debug                 Enable debug logging
           --disable-analysis      Disable the ability to analyze links and pages
           --disable-user-auth     Disable requirement of a valid user API key for all operations
           --host string           Specify the host to bind the service on (default "127.0.0.1")
           --mongo string          Specify the mongodb url (default "mongodb://localhost:27017")
           --name string           Specify a name to the Node or identifying the administrators
           --port string           Specify which port number to bind the service on (default "7856")
           --safebrowsing string   Specify a file path containing your Google SafeBrowsing API key (default disabled)
           --yara string           Specify a path to a file or folder contaning Yara rules

For a more exhaustive documentation on how to install and use PhishDetect please refer to the [Official Documentation](https://docs.phishdetect.io).

## License

PhishDetect Node is released under [GNU Affero General Public License 3.0](LICENSE) and is copyrighted to [Claudio Guarnieri](https://nex.sx).
