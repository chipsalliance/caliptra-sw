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

type Profile uint32
type Status uint32

type RespHdr struct {
	Magic   uint32
	Status  Status
	Profile Profile
}

var count = 1

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

	// Execute the command and generate the response
	// TODO: Implement command execution logic
	fmt.Println(command)
	f, err := os.Create("dat2")
	_, err = f.Write(command)

	fmt.Println(string(command))
	data := Commands(command, n)

	// Create a byte buffer to hold the response
	buffer := new(bytes.Buffer)

	_, err = buffer.Write(data[:])

	// Create a RespHdr struct with the desired values
	/*respHdr := RespHdr{
		Magic:   0x44504552,
		Status:  0,
		Profile: 1,
	}

	// Write the RespHdr struct to the byte buffer
	err = binary.Write(buffer, binary.LittleEndian, &respHdr)
	if err != nil {
		return
	}

	type GetProfileResp struct {
		Profile      Profile
		MajorVersion uint16
		MinorVersion uint16
		VendorId     uint32
		VendorSku    uint32
		MaxTciNodes  uint32
		Flags        uint32
	}

	// Create a GetProfileResp struct with the desired values
	getProfileResp := GetProfileResp{
		Profile:      1,
		MajorVersion: 2,
		MinorVersion: 3,
		VendorId:     4,
		VendorSku:    5,
		MaxTciNodes:  6,
		Flags:        7,
	}

	// Write the GetProfileResp struct to the byte buffer
	err = binary.Write(buffer, binary.LittleEndian, &getProfileResp)
	if err != nil {
		return
	}*/

	// Get the byte slice representation of the response
	resp := buffer.Bytes()
	fmt.Println(resp)

	// Send the response back to the client
	_, err = conn.Write(resp)
	if err != nil {
		log.Printf("Error sending response: %v", err)
		return
	}

	/*if count > 2 {
		conn.Close()
	} else {
		count = count + 1
	}*/

	//log.Printf("| Response Code %#06x", responseCode)
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

	// Delete old socket if necessary
	if _, err := os.Stat(SOCKET_PATH); err == nil {
		cleanup()
	}

	Start()

	/*var cmd []byte
	cmd = []byte{67, 69, 80, 68, 1, 0, 0, 0, 0, 0, 0, 0}

	test := Commands(cmd, 12)
	fmt.Println(test)*/

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
