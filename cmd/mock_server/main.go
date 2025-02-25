package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

// Build:
// go build -o test/mega_server/go -buildvcs=false -gcflags "all=-N -l" ./cmd/mock_server/

// Generate key pair with:
// '
// openssl genrsa -out server.key 2048
// openssl ecparam -genkey -name secp384r1 -out server.key
// openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
const (
	crtFile   = "server.crt"
	keyFile   = "server.key"
	mysqlAddr = "mysql:3306"
	pgAddr    = "postgres:5432"
)

// Handlers contains all HTTP handler methods
type Handlers struct {
	mysqlDB *sql.DB
	pgDB    *sql.DB
}

// NewHandlers creates and initializes a new Handlers instance
func NewHandlers() (*Handlers, error) {
	h := &Handlers{}
	if err := h.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize handlers: %w", err)
	}
	return h, nil
}

// Init initializes the handlers, including database connections
func (h *Handlers) Init() error {
	// MySQL connection
	mysqlDSN := fmt.Sprintf("mysql:mysql@tcp(%s)/megadb", mysqlAddr)
	mysqlDB, err := sql.Open("mysql", mysqlDSN)
	if err != nil {
		return fmt.Errorf("error connecting to mysql: %w", err)
	}
	if err := mysqlDB.Ping(); err != nil {
		mysqlDB.Close()
		return fmt.Errorf("error pinging mysql: %w", err)
	}
	h.mysqlDB = mysqlDB

	// Initialize MySQL schema
	initMySQL := `
        CREATE TABLE IF NOT EXISTS things (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name TEXT NOT NULL,
            quantity INT NOT NULL DEFAULT 0,
            price DECIMAL(10,2) NOT NULL DEFAULT 0.00,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        -- Delete existing data to avoid duplicates on restart
        TRUNCATE TABLE things;

        INSERT INTO things (name, quantity, price)
        VALUES
            ('Widget', 5, 19.99),
            ('Gadget', 10, 5.49),
            ('Doodah', 3, 99.99);
    `

	if _, err := h.mysqlDB.Exec(initMySQL); err != nil {
		h.mysqlDB.Close()
		return fmt.Errorf("error initializing mysql schema: %w", err)
	}

	// PostgreSQL connection
	pgDSN := fmt.Sprintf("postgres://postgres:postgres@%s/megadb?sslmode=disable", pgAddr)
	pgDB, err := sql.Open("postgres", pgDSN)
	if err != nil {
		h.mysqlDB.Close()
		return fmt.Errorf("error connecting to postgres: %w", err)
	}
	if err := pgDB.Ping(); err != nil {
		pgDB.Close()
		h.mysqlDB.Close()
		return fmt.Errorf("error pinging postgres: %w", err)
	}
	h.pgDB = pgDB

	// Initialize PostgreSQL schema
	initSQL := `
        CREATE TABLE IF NOT EXISTS things (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 0,
            price NUMERIC(10,2) NOT NULL DEFAULT 0.00,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );

        -- Delete existing data to avoid duplicates on restart
        TRUNCATE TABLE things;

        INSERT INTO things (name, quantity, price)
        VALUES
            ('Widget', 5, 19.99),
            ('Gadget', 10, 5.49),
            ('Doodah', 3, 99.99);
    `

	if _, err := h.pgDB.Exec(initSQL); err != nil {
		h.pgDB.Close()
		h.mysqlDB.Close()
		return fmt.Errorf("error initializing postgres schema: %w", err)
	}

	return nil
}

func makeRequest(url string) {
	client := &http.Client{
		Transport: &http.Transport{
			// This line forces http1.1:
			TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("error http.NewRequest: %s\n", err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	res, err := client.Do(req)
	if err != nil {
		fmt.Printf("error making http request: %s\n", err)
	}
	fmt.Printf("Response status code: %d\n", res.StatusCode)

	io.ReadAll(res.Body)
}

func StartMockServer(httpPort int, httpsPort int, keyDir string) error {
	handlers, err := NewHandlers()
	if err != nil {
		return fmt.Errorf("failed to create handlers: %w", err)
	}
	defer handlers.mysqlDB.Close()
	defer handlers.pgDB.Close()

	// Handlers
	http.HandleFunc("/large", handlers.Large)
	http.HandleFunc("/chunked", handlers.Chunked)
	http.HandleFunc("/second_http", handlers.SecondHTTP)
	http.HandleFunc("/second_https", handlers.SecondHTTPS)
	http.HandleFunc("/mega_server2", handlers.MegaServer2)
	http.HandleFunc("/mysql_select", handlers.MySQLSelect)
	http.HandleFunc("/mysql_select_prep", handlers.MySQLSelectPrep)
	http.HandleFunc("/mysql_transaction", handlers.MySQLTransaction)
	http.HandleFunc("/psql_select", handlers.PsqlSelect)
	http.HandleFunc("/psql_select_prep", handlers.PsqlSelectPrep)
	http.HandleFunc("/psql_transaction", handlers.PsqlTransaction)
	http.HandleFunc("/{$}", handlers.Root)

	// HTTP server
	go func() {
		fmt.Println("Starting HTTP server on port", httpPort)
		err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", httpPort), nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}()

	// HTTPS server
	crtPath := filepath.Join(keyDir, crtFile)
	keyPath := filepath.Join(keyDir, keyFile)

	fmt.Println("Starting HTTPS server on port", httpsPort)
	err = http.ListenAndServeTLS(fmt.Sprintf("0.0.0.0:%d", httpsPort), crtPath, keyPath, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
	fmt.Println("Started HTTPS server")
	return nil
}

// Root handles GET / and returns a normal response (with Content-Length header)
func (h *Handlers) Root(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /")

	reqID := req.Header.Get("X-Request-ID")
	// makeRequest()
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Request-ID", reqID)

	w.Write([]byte("Hello world.\n"))
}

// Large handles GET /large and returns a large response
func (h *Handlers) Large(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /large")
	// makeRequest()
	w.Header().Set("Content-Type", "text/plain")

	responseBody := []byte{}

	for i := 0; i < 1000; i++ {
		part := strconv.Itoa(i) + ", "
		responseBody = append(responseBody, []byte(part)...)
	}
	responseBody = append(responseBody, []byte("\n")...)
	w.Write(responseBody)
}

// Chunked handles GET /chunked and returns a chunked response
func (h *Handlers) Chunked(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /chunked")

	flusher, ok := w.(http.Flusher)
	if !ok {
		panic("expected http.ResponseWriter to be an http.Flusher")
	}

	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	for i := 1; i <= 5; i++ {
		fmt.Fprintf(w, "Chunk #%d\n", i)
		flusher.Flush() // Trigger "chunked" encoding and send a chunk...
	}
}

// SecondHTTP handles GET /second_http and makes another HTTP request
func (h *Handlers) SecondHTTP(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /second")

	reqID := req.Header.Get("X-Request-ID")

	makeRequest("http://trayce.dev")
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Request-ID", reqID)

	w.Write([]byte("Hello world (second request made).\n"))
}

// MegaServer2 handles GET /mega_server2
func (h *Handlers) MegaServer2(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /mega_server2")

	reqID := req.Header.Get("X-Request-ID")

	makeRequest("http://mega_server2:3001/")
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Request-ID", reqID)

	w.Write([]byte("Hello world (second request made to megaserver2).\n"))
}

// SecondHTTPS handles GET /second_https and makes another HTTPS request
func (h *Handlers) SecondHTTPS(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /second")

	reqID := req.Header.Get("X-Request-ID")

	makeRequest("https://trayce.dev")
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Request-ID", reqID)

	w.Write([]byte("Hello world (second request made).\n"))
}

// MySQLSelect handles GET /mysql_select and returns the count of rows in the things table
func (h *Handlers) MySQLSelect(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /mysql_select")

	query := "SELECT id, name, quantity, price, created_at FROM things"
	rows, err := h.mysqlDB.Query(query)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing query: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Count rows
	rowCount := 0
	for rows.Next() {
		rowCount++
	}

	// Check for errors during iteration
	if err = rows.Err(); err != nil {
		http.Error(w, fmt.Sprintf("Error iterating over rows: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Number of rows returned: %d\n", rowCount)
}

// MySQLSelectPrep handles GET /mysql_select_prep and returns the count of rows using a prepared statement
func (h *Handlers) MySQLSelectPrep(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /mysql_select_prep")

	// Prepare the statement with WHERE clause
	stmt, err := h.mysqlDB.Prepare("SELECT id, name, quantity, price, created_at FROM things WHERE quantity > ?")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error preparing statement: %v", err), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	// Execute the prepared statement with parameter value 1
	rows, err := stmt.Query(1)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing prepared statement: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Count rows
	rowCount := 0
	for rows.Next() {
		rowCount++
	}

	// Check for errors during iteration
	if err = rows.Err(); err != nil {
		http.Error(w, fmt.Sprintf("Error iterating over rows: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Number of rows with quantity > 1: %d\n", rowCount)
}

// MySQLTransaction handles GET /mysql_transaction and performs multiple queries in a transaction
func (h *Handlers) MySQLTransaction(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /mysql_transaction")

	// Start transaction
	tx, err := h.mysqlDB.Begin()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error starting transaction: %v", err), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback() // Rollback if we don't commit

	// Prepare and execute UPDATE
	updateStmt, err := tx.Prepare("UPDATE things SET quantity=123 WHERE id = ?")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error preparing update statement: %v", err), http.StatusInternalServerError)
		return
	}
	defer updateStmt.Close()

	result, err := updateStmt.Exec(1)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing update: %v", err), http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting rows affected: %v", err), http.StatusInternalServerError)
		return
	}

	// Prepare and execute INSERT
	insertStmt, err := tx.Prepare("INSERT INTO things (name, quantity, price) VALUES (?, ?, ?)")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error preparing insert statement: %v", err), http.StatusInternalServerError)
		return
	}
	defer insertStmt.Close()

	result, err = insertStmt.Exec("Something", 5, 19.99)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing insert: %v", err), http.StatusInternalServerError)
		return
	}

	insertID, err := result.LastInsertId()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting last insert ID: %v", err), http.StatusInternalServerError)
		return
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		http.Error(w, fmt.Sprintf("Error committing transaction: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Transaction completed successfully:\n- Updated %d rows\n- Inserted new row with ID %d\n",
		rowsAffected, insertID)
}

// PsqlSelect handles GET /psql_select and returns the count of rows in the things table
func (h *Handlers) PsqlSelect(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /psql_select")

	query := "SELECT id, name, quantity, price, created_at FROM things"
	rows, err := h.pgDB.Query(query)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing query: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Count rows
	rowCount := 0
	for rows.Next() {
		rowCount++
	}

	// Check for errors during iteration
	if err = rows.Err(); err != nil {
		http.Error(w, fmt.Sprintf("Error iterating over rows: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Number of rows returned: %d\n", rowCount)
}

// PsqlSelectPrep handles GET /psql_select_prep and returns the count of rows using a prepared statement
func (h *Handlers) PsqlSelectPrep(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /psql_select_prep")

	// Prepare the statement with WHERE clause
	stmt, err := h.pgDB.Prepare("SELECT id, name, quantity, price, created_at FROM things WHERE quantity > $1")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error preparing statement: %v", err), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	// Execute the prepared statement with parameter value 1
	rows, err := stmt.Query(1)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing prepared statement: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Count rows
	rowCount := 0
	for rows.Next() {
		rowCount++
	}

	// Check for errors during iteration
	if err = rows.Err(); err != nil {
		http.Error(w, fmt.Sprintf("Error iterating over rows: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Number of rows with quantity > 1: %d\n", rowCount)
}

// PsqlTransaction handles GET /psql_transaction and performs multiple queries in a transaction
func (h *Handlers) PsqlTransaction(w http.ResponseWriter, req *http.Request) {
	fmt.Println("GET /psql_transaction")

	// Start transaction
	tx, err := h.pgDB.Begin()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error starting transaction: %v", err), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback() // Rollback if we don't commit

	// Prepare and execute UPDATE
	updateStmt, err := tx.Prepare("UPDATE things SET quantity=$1 WHERE id = $2")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error preparing update statement: %v", err), http.StatusInternalServerError)
		return
	}
	defer updateStmt.Close()

	result, err := updateStmt.Exec(123, 1)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing update: %v", err), http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error getting rows affected: %v", err), http.StatusInternalServerError)
		return
	}

	// Prepare and execute INSERT
	insertStmt, err := tx.Prepare("INSERT INTO things (name, quantity, price) VALUES ($1, $2, $3) RETURNING id")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error preparing insert statement: %v", err), http.StatusInternalServerError)
		return
	}
	defer insertStmt.Close()

	var insertID int64
	err = insertStmt.QueryRow("Something", 5, 19.99).Scan(&insertID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing insert: %v", err), http.StatusInternalServerError)
		return
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		http.Error(w, fmt.Sprintf("Error committing transaction: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Transaction completed successfully:\n- Updated %d rows\n- Inserted new row with ID %d\n",
		rowsAffected, insertID)
}

func main() {
	if err := StartMockServer(4122, 4123, "."); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
