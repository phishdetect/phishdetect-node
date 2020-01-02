// PhishDetect
// Copyright (c) 2018-2020 Claudio Guarnieri.
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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/phishdetect/phishdetect"
	"github.com/phishdetect/phishdetect/brand"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

func compileBrands() []*brand.Brand {
	if brandsPath == "" {
		return nil
	}

	if _, err := os.Stat(brandsPath); os.IsNotExist(err) {
		log.Warning("The specified brands folder does not exist, skipping")
		return nil
	}

	filePaths := []string{}
	filepath.Walk(brandsPath, func(path string, info os.FileInfo, err error) error {
		ext := filepath.Ext(strings.ToLower(path))
		if ext == ".yaml" || ext == ".yml" {
			filePaths = append(filePaths, path)
		}
		return nil
	})

	brands := []*brand.Brand{}

	for _, path := range filePaths {
		log.Debug("Trying to load custom brand file at path ", path)
		customBrand := brand.Brand{}
		yamlFile, err := ioutil.ReadFile(path)
		err = yaml.Unmarshal(yamlFile, &customBrand)
		if err != nil {
			log.Warning("Failed to load brand file: ", err.Error())
			continue
		}

		log.Debug("Loaded custom brand with name: ", customBrand.Name)

		brands = append(brands, &customBrand)
	}

	return brands
}

func loadBrands(analysis phishdetect.Analysis) {
	for _, customBrand := range customBrands {
		// We reset the matches, otherwise we will have polluted results.
		customBrand.Matches = 0
		analysis.Brands.AddBrand(customBrand)
	}

	return
}
