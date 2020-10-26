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
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/phishdetect/phishdetect"
)

type Database struct {
	Client *mongo.Client
	DB     *mongo.Database
}

type User struct {
	UUID      string    `json:"uuid"`
	Name      string    `json:"name" validate:"required"`
	Email     string    `json:"email" validate:"required,email"`
	Key       string    `json:"key"`
	Role      string    `json:"role"`
	Activated bool      `json:"activated"`
	Datetime  time.Time `json:"datetime"`
}

type Indicator struct {
	Type     string    `json:"type"`
	Original string    `json:"original"`
	Hashed   string    `json:"hashed"`
	Tags     []string  `json:"tags"`
	Datetime time.Time `json:"datetime"`
	Owner    string    `json:"owner"`
	Enabled  bool      `json:"enabled"`
}

type Alert struct {
	UUID        string    `json:"uuid"`
	Datetime    time.Time `json:"datetime"`
	Type        string    `json:"type"`
	Match       string    `json:"match"`
	Indicator   string    `json:"indicator"`
	UserContact string    `json:"user_contact" bson:"user_contact"`
	User        string    `json:"user"`
}

type Report struct {
	UUID        string    `json:"uuid"`
	Datetime    time.Time `json:"datetime"`
	Type        string    `json:"type"`
	Content     string    `json:"content"`
	UserContact string    `json:"user_contact" bson:"user_contact"`
	User        string    `json:"user"`
}

type Review struct {
	UUID      string    `json:"uuid"`
	Indicator string    `json:"indicator"`
	Datetime  time.Time `json:"datetime"`
	User      string    `json:"user"`
}

type AnalysisResults struct {
	URL        string                 `json:"url"`
	URLFinal   string                 `json:"url_final" bson:"url_final`
	Safelisted bool                   `json:"safelisted"`
	Dangerous  bool                   `json:"dangerous"`
	Brand      string                 `json:"brand"`
	Score      int                    `json:"score"`
	Screenshot string                 `json:"screenshot"`
	Warnings   []phishdetect.Warning  `json:"warnings"`
	Visits     []string               `json:"visits"`
	Resources  []phishdetect.Resource `json:"resources"`
	HTML       string                 `json:"html"`
	AlertUUID  string                 `json:"uuid"`
}

const IndicatorsLimitAll = 0
const IndicatorsLimit6Months = 1
const IndicatorsLimit24Hours = 2

func NewDatabase(url string) (*Database, error) {
	client, err := mongo.NewClient(options.Client().ApplyURI(url))
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

func (d *Database) GetAllUsers() ([]User, error) {
	var users []User
	coll := d.DB.Collection("users")
	cur, err := coll.Find(context.Background(), bson.D{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(context.Background())

	for cur.Next(context.Background()) {
		var user User
		if err := cur.Decode(&user); err != nil {
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

func (d *Database) ActivateUser(uuid string) error {
	coll := d.DB.Collection("users")

	_, err := coll.UpdateOne(context.Background(), bson.D{{"uuid", uuid}},
		bson.M{"$set": bson.M{"activated": true}})
	if err != nil {
		return err
	}

	return nil
}

func (d *Database) DeactivateUser(uuid string) error {
	coll := d.DB.Collection("users")

	_, err := coll.UpdateOne(context.Background(), bson.D{{"uuid", uuid}},
		bson.M{"$set": bson.M{"activated": false}})
	if err != nil {
		return err
	}

	return nil
}

func (d *Database) AddUser(user User) error {
	coll := d.DB.Collection("users")

	var userFound User
	err := coll.FindOne(context.Background(), bson.D{{"email", user.Email}}).Decode(&userFound)
	if err != nil {
		switch err {
		case mongo.ErrNoDocuments:
		default:
			return err
		}
	}

	_, err = coll.InsertOne(context.Background(), user)
	return err
}

func (d *Database) GetUserByKey(key string) (User, error) {
	coll := d.DB.Collection("users")

	var userFound User
	err := coll.FindOne(context.Background(), bson.D{{"key", key}}).Decode(&userFound)
	if err != nil {
		return User{}, err
	}

	return userFound, nil
}

func (d *Database) GetUserByUUID(uuid string) (User, error) {
	coll := d.DB.Collection("users")

	var userFound User
	err := coll.FindOne(context.Background(), bson.D{{"uuid", uuid}}).Decode(&userFound)
	if err != nil {
		return User{}, err
	}

	return userFound, nil
}

func (d *Database) GetIndicators(limit int, enabled bool) ([]Indicator, error) {
	var iocs []Indicator
	coll := d.DB.Collection("indicators")

	now := time.Now().UTC()

	var filter bson.M

	switch limit {
	case IndicatorsLimitAll:
		filter = bson.M{"enabled": enabled}
	case IndicatorsLimit6Months:
		filter = bson.M{
			"datetime": bson.M{
				"$gte": now.AddDate(0, -6, 0),
			},
			"enabled": enabled,
		}
	case IndicatorsLimit24Hours:
		filter = bson.M{
			"datetime": bson.M{
				"$gte": now.Add(-24 * time.Hour),
			},
			"enabled": enabled,
		}
	}

	cur, err := coll.Find(context.Background(), filter)
	if err != nil {
		return nil, err
	}
	defer cur.Close(context.Background())

	for cur.Next(context.Background()) {
		var ioc Indicator
		if err := cur.Decode(&ioc); err != nil {
			continue
		}
		iocs = append(iocs, ioc)
	}

	return iocs, nil
}

func (d *Database) GetIndicatorByHash(hash string) (Indicator, error) {
	coll := d.DB.Collection("indicators")

	var ioc Indicator
	err := coll.FindOne(context.Background(), bson.D{{"hashed", hash}}).Decode(&ioc)
	if err != nil {
		return Indicator{}, err
	}

	return ioc, nil
}

func (d *Database) AddIndicator(ioc Indicator) error {
	coll := d.DB.Collection("indicators")

	var iocFound Indicator
	err := coll.FindOne(context.Background(), bson.D{{"hashed", ioc.Hashed}}).Decode(&iocFound)
	// First, we check if an error was returned.
	// If it's ErrNoDocuments, then it's all good: it just means that there is
	// no record created yet. If we get a different error, it means something
	// failed in the query, so we actually retun straight away.
	if err != nil {
		switch err {
		case mongo.ErrNoDocuments:
		default:
			return err
		}
	} else {
		// If no error is returned, it means that a record for the particular
		// indicator already exists.
		// NOTE: In this case we refresh the datetime in order to make sure it
		//       is served again. The rationale behind this is that if an IOC
		//       was re-added it might be because it is being re-used after
		//       the first discovery. Updating the datetime will make sure that
		//       the IOC is served in the list of last 24h/6 months feed.
		_, err = coll.UpdateOne(context.Background(), bson.D{{"hashed", ioc.Hashed}},
			bson.M{"$set": bson.M{"datetime": time.Now().UTC()}})
		if err != nil {
			return err
		}
		return fmt.Errorf("This is an already known indicator")
	}

	_, err = coll.InsertOne(context.Background(), ioc)
	return err
}

func (d *Database) UpdateIndicator(ioc Indicator) error {
	coll := d.DB.Collection("indicators")

	var iocFound Indicator
	err := coll.FindOne(context.Background(), bson.D{{"hashed", ioc.Hashed}}).Decode(&iocFound)
	if err != nil {
		return err
	}

	_, err = coll.UpdateOne(context.Background(), bson.D{{"hashed", ioc.Hashed}},
		bson.M{"$set": bson.M{
			"datetime": time.Now().UTC(),
			"tags":     ioc.Tags,
			"enabled":  ioc.Enabled,
		}})

	return err
}

func (d *Database) GetAllAlerts(offset, limit int64) ([]Alert, error) {
	coll := d.DB.Collection("alerts")

	opts := options.Find()
	opts.SetSort(bson.D{{"datetime", -1}})
	if offset > 0 {
		opts.SetSkip(offset)
	}
	if limit > 0 {
		opts.SetLimit(limit)
	}
	cur, err := coll.Find(context.Background(), bson.D{}, opts)
	if err != nil {
		return nil, err
	}
	defer cur.Close(context.Background())

	alerts := []Alert{}
	for cur.Next(context.Background()) {
		var alert Alert
		if err := cur.Decode(&alert); err != nil {
			continue
		}
		alerts = append(alerts, alert)
	}

	return alerts, nil
}

func (d *Database) AddAlert(alert Alert) error {
	coll := d.DB.Collection("alerts")

	_, err := coll.InsertOne(context.Background(), alert)
	return err
}

func (d *Database) GetAllReports(offset, limit int64, reportType string) ([]Report, error) {
	coll := d.DB.Collection("reports")

	opts := options.Find()
	opts.SetSort(bson.D{{"datetime", -1}})
	if offset > 0 {
		opts.SetSkip(offset)
	}
	if limit > 0 {
		opts.SetLimit(limit)
	}

	filter := bson.D{}
	if reportType != "" {
		filter = bson.D{{"type", reportType}}
	}

	cur, err := coll.Find(context.Background(), filter, opts)
	if err != nil {
		return nil, err
	}
	defer cur.Close(context.Background())

	reports := []Report{}
	for cur.Next(context.Background()) {
		var report Report
		if err := cur.Decode(&report); err != nil {
			continue
		}
		reports = append(reports, report)
	}

	return reports, nil
}

func (d *Database) AddReport(report Report) error {
	coll := d.DB.Collection("reports")

	_, err := coll.InsertOne(context.Background(), report)
	return err
}

func (d *Database) GetReportByUUID(uuid string) (Report, error) {
	coll := d.DB.Collection("reports")

	var report Report
	err := coll.FindOne(context.Background(), bson.D{{"uuid", uuid}}).Decode(&report)
	if err != nil {
		return Report{}, err
	}

	return report, nil
}

func (d *Database) AddReview(review Review) error {
	coll := d.DB.Collection("reviews")

	_, err := coll.InsertOne(context.Background(), review)
	return err
}

func (d *Database) AddAnalysisResults(results AnalysisResults) error {
	coll := d.DB.Collection("analysisresults")

	_, err := coll.InsertOne(context.Background(), results)
	return err
}
