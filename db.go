package main

import (
	"database/sql"
	"errors"
	"fmt"

	wl_db "github.com/wsva/lib_go_db"
	"golang.org/x/crypto/bcrypt"
)

type Account struct {
	UserID      string `json:"UserID"`
	Nickname    string `json:"Nickname"`
	Username    string `json:"Username"`
	Number      string `json:"Number"`
	Email       string `json:"Email"`
	Password    string `json:"Password"`
	IsSuperuser string `json:"IsSuperuser"`
	IsStaff     string `json:"IsStaff"`
	IsActive    string `json:"IsActive"`
}

func (a *Account) DBInsert(db *wl_db.Config) error {
	switch db.Driver {
	case wl_db.DriverPostgreSQL:
		query := "insert into oauth2_user values ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
		_, err := db.Exec(query, a.UserID, a.Nickname, a.Username, a.Number, a.Email, a.Password, "N", "N", "Y")
		return err
	default:
		return fmt.Errorf("invalid DBType %v", db.Driver)
	}
}

// will set user_id, nickname, email
func (a *Account) Verify(db *wl_db.Config) error {
	var row *sql.Row
	var err error
	switch db.Driver {
	case wl_db.DriverPostgreSQL:
		query := "select user_id, nickname, email, password from oauth2_user " +
			"where (nickname=$1 or email=$2) and is_active='Y'"
		row, err = db.QueryRow(query, a.Nickname, a.Email)
	default:
		return fmt.Errorf("invalid DBType %v", db.Driver)
	}
	if err != nil {
		return err
	}
	var f1, f2, f3, f4 sql.NullString
	err = row.Scan(&f1, &f2, &f3, &f4)
	if err != nil {
		return err
	}
	err = bcrypt.CompareHashAndPassword([]byte(f4.String), []byte(a.Password))
	if err != nil {
		return errors.New("verify password failed")
	}
	a.UserID = f1.String
	a.Nickname = f2.String
	a.Email = f3.String
	return nil
}

func (a *Account) DBQuery(db *wl_db.Config) error {
	var row *sql.Row
	var err error
	switch db.Driver {
	case wl_db.DriverPostgreSQL:
		query := "select a.nickname, a.username, a.number, a.email, a.is_superuser, a.is_staff " +
			"from oauth2_user a " +
			"where a.user_id=$1 and a.is_active='Y'"
		row, err = db.QueryRow(query, a.UserID)
	default:
		return fmt.Errorf("invalid DBType %v", db.Driver)
	}
	if err != nil {
		return err
	}
	var f1, f2, f3, f4, f5, f6 sql.NullString
	err = row.Scan(&f1, &f2, &f3, &f4, &f5, &f6)
	if err != nil {
		return err
	}
	a.Nickname = f1.String
	a.Username = f2.String
	a.Number = f3.String
	a.Email = f4.String
	a.IsSuperuser = f5.String
	a.IsStaff = f6.String
	return nil
}

func (a *Account) DBUpdate(db *wl_db.Config) error {
	switch db.Driver {
	case wl_db.DriverPostgreSQL:
		query := "update oauth2_user set " +
			"nickname=$1, username=$2, number=$3, email=$4, is_superuser=$5, is_staff=$6, is_active=$7 " +
			"where user_id=$8"
		_, err := db.Exec(query, a.Nickname, a.Username, a.Number, a.Email, a.IsSuperuser, a.IsStaff, a.IsActive, a.UserID)
		if err != nil {
			return err
		}
		if a.Password != "" {
			query := "update oauth2_user set password=$1 where user_id=$2"
			_, err := db.Exec(query, a.Password, a.UserID)
			return err
		}
		return nil
	default:
		return fmt.Errorf("invalid DBType %v", db.Driver)
	}
}

func QueryAccountAll(db *wl_db.Config) ([]Account, error) {
	var rows *sql.Rows
	var err error
	var result []Account
	switch db.Driver {
	case wl_db.DriverPostgreSQL:
		query := fmt.Sprint("select a.user_id, a.nickname, a.username, a.number, a.email, a.is_superuser, a.is_staff, a.is_active " +
			"from oauth2_user a")
		rows, err = db.Query(query)
	default:
		return nil, fmt.Errorf("invalid DBType %v", db.Driver)
	}
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f1, f2, f3, f4, f5, f6, f7, f8 sql.NullString
		err = rows.Scan(&f1, &f2, &f3, &f4, &f5, &f6, &f7, &f8)
		if err != nil {
			return nil, err
		}
		res := Account{
			UserID:      f1.String,
			Nickname:    f2.String,
			Username:    f3.String,
			Number:      f4.String,
			Email:       f5.String,
			IsSuperuser: f6.String,
			IsStaff:     f7.String,
			IsActive:    f5.String,
		}
		result = append(result, res)
	}
	rows.Close()
	return result, nil
}

type Token struct {
	AccessToken  string
	RefreshToken string
	ClientID     string
	UserID       string
	IP           string
}

func (t *Token) DBInsert(db *wl_db.Config) error {
	switch db.Driver {
	case wl_db.DriverPostgreSQL:
		query := "INSERT INTO oauth2_token VALUES ($1, $2, $3, $4, $5)"
		_, err := db.Exec(query, t.AccessToken, t.RefreshToken, t.ClientID, t.UserID, t.IP)
		return err
	default:
		return fmt.Errorf("invalid DBType %v", db.Driver)
	}
}

func (t *Token) DBDelete(db *wl_db.Config) error {
	switch db.Driver {
	case wl_db.DriverPostgreSQL:
		query := "delete from oauth2_token where access_token=$1"
		_, err := db.Exec(query, t.AccessToken)
		return err
	default:
		return fmt.Errorf("invalid DBType %v", db.Driver)
	}
}

// return token, nickname, error
func (t *Token) DBQuery(db *wl_db.Config) (*Token, string, error) {
	var row *sql.Row
	var err error
	switch db.Driver {
	case wl_db.DriverPostgreSQL:
		query := "select t.refresh_token, t.client_id, t.user_id, t.ip, a.nickname " +
			"from oauth2_token t, oauth2_user a " +
			"where t.user_id=a.user_id and t.access_token=$1"
		row, err = db.QueryRow(query, t.AccessToken)
	default:
		return nil, "", fmt.Errorf("invalid DBType %v", db.Driver)
	}
	if err != nil {
		return nil, "", err
	}
	var f1, f2, f3, f4, f5 sql.NullString
	err = row.Scan(&f1, &f2, &f3, &f4, &f5)
	if err != nil {
		return nil, "", errors.New("token revoked")
	}
	t.RefreshToken = f1.String
	t.ClientID = f2.String
	t.UserID = f3.String
	t.IP = f4.String
	return t, f5.String, nil
}
