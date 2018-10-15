// PhishDetect
// Copyright (C) 2018  Claudio Guarnieri
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
	"context"
	"time"

	// "github.com/mongodb/mongo-go-driver/bson"
	"github.com/mongodb/mongo-go-driver/mongo"
)

// var db *Database

type Database struct {
	Client *mongo.Client
	DB     *mongo.Database
}

type Indicator struct {
	Type     string    `json:"type"`
	Original string    `json:"original"`
	Hashed   string    `json:"hashed"`
	Tags     []string  `json:"tags"`
	Datetime time.Time `json:"datetime"`
}

func NewDatabase() (*Database, error) {
	client, err := mongo.NewClient("mongodb://localhost:27017")
	if err != nil {
		return nil, err
	}
	err = client.Connect(context.TODO())
	if err != nil {
		return nil, err
	}
	db := client.Database("phishdetect")

	return &Database{
		Client: client,
		DB:     db,
	}, nil
}

func (d *Database) Close() {
	d.Client.Disconnect(context.Background())
}

func (d *Database) GetIndicators() ([]Indicator, error) {
	coll := d.DB.Collection("indicators")
	_, err := coll.Find(context.Background(), nil)
	if err != nil {
		return nil, err
	}

	var iocs []Indicator
	return iocs, nil
}

func (d *Database) AddIndicator(indicatorType string, indicator string, tags []string) error {
	ioc := Indicator{
		Type:     indicatorType,
		Original: indicator,
		Hashed:   encodeSHA256(indicator),
		Tags:     tags,
		Datetime: time.Now().UTC(),
	}

	coll := d.DB.Collection("indicators")

    var curIoc Indicator
    err := coll.FindOne(context.Background(), map[string]string{"original": indicator}).Decode(curIoc)
    if err == nil {
        return fmt.Errorf("This is an already known indicator")
    } else {
        return err
    }

	_, err = coll.InsertOne(context.Background(), ioc)
	return err
}

func GetEvents() {

}

func AddEvent() {

}
