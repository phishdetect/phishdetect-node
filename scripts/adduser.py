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

import argparse
import secrets
from pymongo import MongoClient

client = MongoClient()
db = client.phishdetect

def main():
    parser = argparse.ArgumentParser(description="Add a user to the database")
    parser.add_argument('--admin', action='store_true', help="Enable if the user is an administrator")
    parser.add_argument('name', type=str, help="Name of the user")
    parser.add_argument('email', type=str, help="Email of the user")
    args = parser.parse_args()

    name = args.name
    email = args.email

    role = 'submitter'
    if args.admin:
        role = 'admin'

    key = secrets.token_urlsafe(16)

    user = db.users.find_one({'email': email})
    if user:
        print("The user \"{}\" already exists with API key: {}".format(
            user['name'], user['key']))
        return

    db.users.insert_one({
        'name': name,
        'email': email,
        'key': key,
        'role': role,
    })
    print("User \"{}\" added!".format(name))
    print("The API key is: {}".format(key))

if __name__ == '__main__':
    main()
