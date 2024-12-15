package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql" // MySQL driver
)

func main() {
	// MySQL connection details
	dsn := "root:root@tcp(172.17.0.3:3306)/my_database"

	// Connect to the database
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}
	defer db.Close()

	// Test the connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Error pinging the database: %v", err)
	}

	fmt.Println("Successfully connected to the database!")

	// Query the database
	query := "SELECT id, name, quantity, price, created_at FROM things"
	rows, err := db.Query(query)
	if err != nil {
		log.Fatalf("Error executing query: %v", err)
	}
	defer rows.Close()

	// Count rows
	rowCount := 0
	for rows.Next() {
		rowCount++
	}

	// Check for errors during iteration
	if err = rows.Err(); err != nil {
		log.Fatalf("Error iterating over rows: %v", err)
	}

	fmt.Printf("Number of rows returned: %d\n", rowCount)
}
