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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/phishdetect/phishdetect"
	"github.com/phishdetect/phishdetect/brand"
)

type CustomBrands struct {
	Path   string
	Brands []brand.Brand
}

func (b *CustomBrands) CompileBrands() error {
	if b.Path == "" {
		return nil
	}

	if _, err := os.Stat(b.Path); os.IsNotExist(err) {
		return fmt.Errorf("The specified brands folder does not exist, skipping")
	}

	filePaths := []string{}
	filepath.Walk(b.Path, func(path string, info os.FileInfo, err error) error {
		ext := filepath.Ext(strings.ToLower(path))
		if ext == ".yaml" || ext == ".yml" {
			filePaths = append(filePaths, path)
		}
		return nil
	})

	b.Brands = []brand.Brand{}
	for _, path := range filePaths {
		log.Debug("Trying to load custom brand file at path ", path)
		customBrand := brand.Brand{}
		yamlFile, err := ioutil.ReadFile(path)
		err = yaml.Unmarshal(yamlFile, &customBrand)
		if err != nil {
			log.Warning("Failed to load brand file: ", err.Error())
			continue
		}

		b.Brands = append(b.Brands, customBrand)
		log.Debug("Loaded custom brand with name: ", customBrand.Name)
	}

	log.Info("Loaded ", len(b.Brands), " custom brand definitions")

	return nil
}

func (b *CustomBrands) LoadBrands(analysis phishdetect.Analysis) {
	for _, customBrand := range b.Brands {
		log.Debug("Adding brand with name ", customBrand.Name, " to analysis")
		newBrand := customBrand
		analysis.Brands.AddBrand(&newBrand)
	}
}

func (b *CustomBrands) WatchBrandsFolder() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("Unable to create a filesystem watch for brands folder: %s", err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Remove == fsnotify.Remove {
					log.Info("The file ", event.Name, " was modified in brands folder ", b.Path)
					b.CompileBrands()
				}
			}
		}
	}()

	err = watcher.Add(b.Path)
	if err != nil {
		if err.Error() == "no space left on device" {
			return fmt.Errorf("You might be out of inotify watches, increase the value of " +
				"fs.inotify.max_user_watches in /etc/sysctl.conf")
		}
		return fmt.Errorf("Unable to add %s to filesystem watcher: %s", b.Path, err)
	}
	<-done

	log.Info("Filesystem watcher for brands folder ", b.Path, " started")

	return nil
}
