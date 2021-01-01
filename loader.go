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
	"bytes"
	"io"
	"path"

	"github.com/gobuffalo/packr"
)

// Thanks to @12foo
// https://github.com/flosch/pongo2/issues/192#issuecomment-507024493

type packrBoxLoader struct {
	box *packr.Box
}

func (l packrBoxLoader) Abs(base, name string) string {
	p := path.Join(path.Dir(base), name)
	return p
}

func (l packrBoxLoader) Get(path string) (io.Reader, error) {
	b, err := l.box.MustBytes(path)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}
