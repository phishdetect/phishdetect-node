// PhishDetect
// Copyright (c) 2018-2021 Claudio Guarnieri.
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
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/phishdetect/phishdetect"
	"github.com/phishdetect/phishdetect/brands"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

type CustomBrands struct {
	Path   string
	Brands []brands.Brand
}

func (b *CustomBrands) CompileBrands() error {
	if b.Path == "" {
		return nil
	}

	if _, err := os.Stat(b.Path); os.IsNotExist(err) {
		return errors.New("The specified brands folder does not exist, skipping")
	}

	filePaths := []string{}
	filepath.Walk(b.Path, func(path string, info os.FileInfo, err error) error {
		ext := filepath.Ext(strings.ToLower(path))
		if ext == ".yaml" || ext == ".yml" {
			filePaths = append(filePaths, path)
		}
		return nil
	})

	b.Brands = []brands.Brand{}
	for _, path := range filePaths {
		log.Debug().Str("path", path).Msg("Trying to load custom brand file")
		customBrand := brands.Brand{}
		yamlFile, err := ioutil.ReadFile(path)
		err = yaml.Unmarshal(yamlFile, &customBrand)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to load brand file")
			continue
		}

		b.Brands = append(b.Brands, customBrand)
		log.Debug().Str("brand_name", customBrand.Name).Msg("Loaded custom brand")
	}

	log.Info().Int("total", len(b.Brands)).Msg("Loaded custom brand definitions")

	return nil
}

func (b *CustomBrands) LoadBrands(analysis phishdetect.Analysis) {
	for _, customBrand := range b.Brands {
		log.Debug().Str("brand_name", customBrand.Name).Msg("Adding custom brand to analysis")
		newBrand := customBrand
		analysis.Brands.AddBrand(&newBrand)
	}
}
