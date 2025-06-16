package db

import (
    "github.com/jackc/pgx/v4"
	"context"
    "log"
)


var Conn *pgx.Conn

func ConnectDB() {
	var err error

	dsn := "postgres://postgres:@localhost:5432/edu" // 👈 change this
	Conn, err = pgx.Connect(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}
	log.Println("Connected to PostgreSQL.")
}
