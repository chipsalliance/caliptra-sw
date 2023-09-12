package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const (
	SOCKET_PATH = "/tmp/dpe-emu.socket"
	BUFFER_SIZE = 4096
)

func handleRequest(conn net.Conn) {

	defer conn.Close()

	buf := make([]byte, BUFFER_SIZE)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Error reading command: %v", err)
		return
	}

	locality := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
	command := buf[4:n]

	log.Printf("----------------------------------")
	log.Printf("| Locality `%#x` requested %x", locality, command)
	log.Printf("|")

	data := Commands(command)

	buffer := new(bytes.Buffer)

	_, err = buffer.Write(data[:])

	resp := buffer.Bytes()
	fmt.Println(resp)

	// Send the response back to the client
	_, err = conn.Write(resp)
	if err != nil {
		log.Printf("Error sending response: %v", err)
		return
	}

	log.Printf("----------------------------------")
}

func cleanup() {
	err := os.Remove(SOCKET_PATH)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("Unable to unlink %s: %v", SOCKET_PATH, err)
	}
}

func main() {
	// Initialize logging
	fmt.Println("Server is listening 1")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Delete old socket
	if _, err := os.Stat(SOCKET_PATH); err == nil {
		cleanup()
	}

	// Start the Emulator
	Start()

	// Create a Unix socket listener
	listener, err := net.Listen("unix", SOCKET_PATH)
	if err != nil {
		log.Fatalf("Failed to create socket listener: %v", err)
	}
	fmt.Println("Server is listening 2")
	defer listener.Close()

	// Handle cleanup on program exit
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		cleanup()
		os.Exit(0)
	}()

	log.Printf("DPE listening to socket %s", SOCKET_PATH)

	// Accept and handle incoming connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			break
		}

		go handleRequest(conn)
	}
}
