package controllers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins
	},
}

func WSScan(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("upgrade error: %v", err)
		return
	}
	defer conn.Close()

	// Connect to SQLite database
	db, err := sql.Open("sqlite3", "./targets.db")
	if err != nil {
		log.Printf("database connection error: %v", err)
		return
	}
	defer db.Close()

	// Query all domains and IPs from the database
	rows, err := db.Query("SELECT type, value FROM targets")
	if err != nil {
		log.Printf("database query error: %v", err)
		return
	}
	defer rows.Close()

	// Prepare command to run nmap
	cmd := exec.Command("nmap", "-A", "-Pn", "-T4")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Printf("stdin pipe error: %v", err)
		return
	}
	defer stdin.Close()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("stdout pipe error: %v", err)
		return
	}
	defer stdout.Close()

	err = cmd.Start()
	if err != nil {
		log.Printf("command start error: %v", err)
		return
	}

	// Send nmap command output to WebSocket client
	go func() {
		for rows.Next() {
			var target, value string
			if err := rows.Scan(&target, &value); err != nil {
				log.Printf("database scan error: %v", err)
				continue
			}
			targetInfo := map[string]string{"type": target, "value": value}
			jsonData, err := json.Marshal(targetInfo)
			if err != nil {
				log.Printf("json marshal error: %v", err)
				continue
			}
			if err := conn.WriteMessage(websocket.TextMessage, jsonData); err != nil {
				log.Printf("websocket write error: %v", err)
				break
			}
			// Write target value to nmap stdin
			if _, err := stdin.Write([]byte(value + "\n")); err != nil {
				log.Printf("stdin write error: %v", err)
				break
			}
		}
		cmd.Wait() // Wait for nmap command to complete
	}()

	// Read nmap command output and send to WebSocket client
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				log.Printf("stdout read error: %v", err)
				break
			}
			if err := conn.WriteMessage(websocket.TextMessage, buf[:n]); err != nil {
				log.Printf("websocket write error: %v", err)
				break
			}
		}
	}()

	// Handle WebSocket closure
	conn.SetCloseHandler(func(code int, text string) error {
		log.Printf("WebSocket closed with code %d: %s", code, text)
		err := cmd.Process.Kill()
		if err != nil {
			log.Printf("failed to kill nmap process: %v", err)
		}
		return nil
	})

	// Wait for the WebSocket connection to close
	select {}
}
