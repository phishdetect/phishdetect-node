#!/usr/bin/env python3
# PhishDetect
# Copyright (C) 2018  Claudio Guarnieri
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys
import argparse
import requests
import traceback

def main():
    parser = argparse.ArgumentParser(description="Fetch events from the PhishDetect Node")
    parser.add_argument('--url', default='http://127.0.0.1:7856', help="URL to the PhishDetect Node")
    parser.add_argument('--key', required=True, help="The API key for your PhishDetect Node user")
    args = parser.parse_args()

    data = {'key': args.key}

    url = args.url + '/api/events/fetch/'

    try:
        res = requests.post(url, json=data)
        data = res.json()
    except Exception as e:
        traceback.print_exc()
        sys.exit(-1)

    if res.status_code != 200:
        print("ERROR: I received an error while trying to fetch events")
        if "msg" in data:
            print(data["msg"])

        return

    for event in data:
        print("Datetime: {}".format(event['datetime']))
        print("Type: {}".format(event['type']))
        print("Indicator: {}".format(event['indicator']))
        print("Hashed: {}".format(event['hashed']))
        print("Target Contact: {}".format(event['target_contact']))
        print("UUID: {}".format(event['uuid']))
        print("")

if __name__ == '__main__':
    main()
