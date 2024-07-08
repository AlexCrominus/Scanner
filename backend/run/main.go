package main

import (
	"log"
	"scanner/routes"
)

func main() {
	router := routes.SetupRouter()

	if err := router.Run(":8000"); err != nil {
		log.Fatalf("Could not run the server: %v", err)
	}
}
