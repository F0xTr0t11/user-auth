package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"unicode"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string
	Password string
}

func initDB() *sql.DB {
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatalf("Failed to open the database: %v", err)
	}
	createTableSQL := `CREATE TABLE IF NOT EXISTS users (
        "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        "username" TEXT NOT NULL UNIQUE,
        "password" TEXT NOT NULL
    );`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
	return db
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func RegisterUser(db *sql.DB, user User) error {
	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		return err
	}

	insertUserSQL := `INSERT INTO users (username, password) VALUES (?, ?)`
	_, err = db.Exec(insertUserSQL, user.Username, hashedPassword)
	return err
}

func AuthenticateUser(db *sql.DB, user User) bool {
	var hashedPassword string
	query := `SELECT password FROM users WHERE username = ?`
	err := db.QueryRow(query, user.Username).Scan(&hashedPassword)
	if err != nil {
		return false
	}
	return CheckPasswordHash(user.Password, hashedPassword)
}

func ValidateUserInput(username, password string) error {
	if len(username) > 15 {
		return errors.New("username must be 15 characters or less")
	}
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return errors.New("password must contain at least one uppercase letter, one lowercase letter, and one special character")
	}
	return nil
}

func main() {
	db := initDB()
	defer db.Close()

	var choice string

	for {
		fmt.Println("Welcome to User Registration and Authentication")
		fmt.Println("1. Register")
		fmt.Println("2. Authenticate")
		fmt.Print("Enter your choice (1 or 2): ")
		fmt.Scan(&choice)

		if choice != "1" && choice != "2" {
			fmt.Println("Invalid choice! Please enter 1 or 2.")
			continue
		}

		var user User
		fmt.Print("Enter username: ")
		fmt.Scan(&user.Username)
		fmt.Print("Enter password: ")
		fmt.Scan(&user.Password)

		if err := ValidateUserInput(user.Username, user.Password); err != nil {
			fmt.Println("Error:", err)
			return
		}

		switch choice {
		case "1":
			err := RegisterUser(db, user)
			if err != nil {
				if err.Error() == "UNIQUE constraint failed: users.username" {
					fmt.Println("Error: Username already exists!")
				} else {
					fmt.Println("Error registering user:", err)
				}
			} else {
				fmt.Println("User registered successfully!")
			}
		case "2":
			if AuthenticateUser(db, user) {
				fmt.Println("Authentication successful!")
			} else {
				fmt.Println("Authentication failed!")
			}
		}
		break
	}
}
