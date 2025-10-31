package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("mysql", "phpmyadmin:new_password@tcp(localhost:3306)/event_planner?parseTime=true")
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	log.Println("Connected to MySQL database")

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INT AUTO_INCREMENT PRIMARY KEY,
		username VARCHAR(50) UNIQUE NOT NULL,
		password VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}

	log.Println("Users table ensured")

	http.HandleFunc("/register", corsMiddleware(registerHandler))
	http.HandleFunc("/login", corsMiddleware(loginHandler))
	http.HandleFunc("/users", corsMiddleware(usersHandler))

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(user.Username) < 3 || len(user.Password) < 3 {
		sendErrorResponse(w, "Username and password must be at least 3 characters", http.StatusBadRequest)
		return
	}

	var existingUser string
	err = db.QueryRow("SELECT username FROM users WHERE username = ?", user.Username).Scan(&existingUser)
	if err != sql.ErrNoRows {
		if err == nil {
			sendErrorResponse(w, "Username already exists", http.StatusBadRequest)
			return
		} else {
			sendErrorResponse(w, "Database error", http.StatusInternalServerError)
			return
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		sendErrorResponse(w, "Failed to process password", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, string(hashedPassword))
	if err != nil {
		sendErrorResponse(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(Response{
		Message: "User registered successfully",
		Success: true,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var storedPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", user.Username).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			sendErrorResponse(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		sendErrorResponse(w, "Database error", http.StatusInternalServerError)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(user.Password)) != nil {
		sendErrorResponse(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Message: "Login successful",
		Success: true,
	})
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	type UserRecord struct {
		ID        int       `json:"id"`
		Username  string    `json:"username"`
		CreatedAt time.Time `json:"created_at"`
	}

	rows, err := db.Query("SELECT id, username, created_at FROM users")
	if err != nil {
		sendErrorResponse(w, "Failed to fetch users", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []UserRecord
	for rows.Next() {
		var user UserRecord
		err := rows.Scan(&user.ID, &user.Username, &user.CreatedAt)
		if err != nil {
			sendErrorResponse(w, "Failed to scan user", http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(Response{
		Message: message,
		Success: false,
	})
}
