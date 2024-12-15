package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
)

type Thing struct {
	ID        int
	Name      string
	Quantity  int
	Price     float64
	CreatedAt time.Time
}

func main() {
	// Update this connection string to match your PostgreSQL environment
	// For example: "postgres://username:password@localhost:5432/mydb?sslmode=disable"
	connStr := "postgres://postgres:postgres@172.17.0.3:5432/postgres?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v\n", err)
	}
	defer db.Close()

	// Verify connection
	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v\n", err)
	}

	// Prepare the statement
	stmt, err := db.Prepare("SELECT id, name, quantity, price, created_at FROM things WHERE id > $1")
	if err != nil {
		log.Fatalf("Failed to prepare statement: %v\n", err)
	}
	defer stmt.Close()

	// Execute the prepared statement with the parameter
	rows, err := stmt.Query(1)
	if err != nil {
		log.Fatalf("Failed to execute query: %v\n", err)
	}
	defer rows.Close()

	var things []Thing
	for rows.Next() {
		var t Thing
		err := rows.Scan(&t.ID, &t.Name, &t.Quantity, &t.Price, &t.CreatedAt)
		if err != nil {
			log.Printf("Failed to scan row: %v\n", err)
			continue
		}
		things = append(things, t)
	}

	if err = rows.Err(); err != nil {
		log.Printf("Error encountered during iteration: %v\n", err)
	}

	// Print the results
	for _, thing := range things {
		fmt.Printf("ID: %d, Name: %s, Quantity: %d, Price: %.2f, CreatedAt: %s\n",
			thing.ID, thing.Name, thing.Quantity, thing.Price, thing.CreatedAt)
	}
}
