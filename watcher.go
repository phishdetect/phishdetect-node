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
	"os"
	"path"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

func watchFolder(folder string, callback func()) error {
	if _, err := os.Stat(folder); os.IsNotExist(err) {
		return fmt.Errorf("The specified folder does not exist at path %s", folder)
	}

	folderStat, err := os.Stat(folder)
	if err != nil {
		return err
	}

	switch mode := folderStat.Mode(); {
	case mode.IsRegular():
		// We make sure the path is a folder, for example in the case a
		// Yara "index" file with includes is passed as argument, instead
		// of a full folder.
		folder = path.Dir(folder)
	}

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
					log.Info("The file ", event.Name, " was modified in folder ", folder)
					callback()
				}
			}
		}
	}()

	log.Info("Launching filesystem watcher for folder: ", folder)
	err = watcher.Add(folder)
	if err != nil {
		if err.Error() == "no space left on device" {
			return fmt.Errorf("You might be out of inotify watches, increase the value of " +
				"fs.inotify.max_user_watches in /etc/sysctl.conf")
		}
		return fmt.Errorf("Unable to add %s to filesystem watcher: %s", folder, err)
	}
	<-done

	log.Info("Filesystem watcher for folder ", folder, " started")

	return nil
}
