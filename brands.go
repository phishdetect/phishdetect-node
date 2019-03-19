// PhishDetect
// Copyright (c) 2018-2019 Claudio Guarnieri.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"os"
	"path/filepath"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"github.com/phishdetect/phishdetect/brand"
)

func loadBrands() (brands []*brand.Brand) {
	if brandsPath == "" {
		return
	}

	if _, err := os.Stat(brandsPath); os.IsNotExist(err) {
		log.Warning("The specified brands folder does not exist, skipping")
		return
	}

	filepath.Walk(brandsPath, func(path string, info os.FileInfo, err error) error {
		brand := &brand.Brand{}
		yamlFile, err := ioutil.ReadFile(path)
		err = yaml.Unmarshal(yamlFile, brand)
		if err != nil {
			return err
		}
		brands = append(brands, brand)
		return nil
	})

	return brands
}