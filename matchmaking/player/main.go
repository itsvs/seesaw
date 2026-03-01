package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type Player struct {
	ID       string    `json:"id"`
	JoinTime time.Time `json:"join_time"`
}

type StatusResponse struct {
	QueueSize         int         `json:"queue_size"`
	GameServers       int         `json:"game_servers"`
	PlayerQueue       []Player    `json:"player_queue"`
	GameServersDetail []GameServer `json:"game_servers_detail"`
}

type GameServer struct {
	ID      string   `json:"id"`
	Port    int      `json:"port"`
	Players []Player `json:"players"`
	MaxSize int      `json:"max_size"`
}

func main() {
	playerID := flag.String("id", "", "Player ID")
	coordinatorURL := flag.String("coordinator", "http://localhost:8000", "Coordinator server URL")
	flag.Parse()

	if *playerID == "" {
		log.Fatal("Player ID is required. Use -id flag")
	}

	player := Player{
		ID: *playerID,
	}

	if err := enqueuePlayer(player, *coordinatorURL); err != nil {
		log.Fatalf("Failed to enqueue player: %v", err)
	}

	log.Printf("Player %s enqueued successfully", *playerID)

	for {
		status, err := getStatus(*coordinatorURL)
		if err != nil {
			log.Printf("Failed to get status: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		assigned := checkIfAssigned(*playerID, status)
		if assigned != nil {
			log.Printf("Player %s assigned to game %s on port %d with %d players", 
				*playerID, assigned.ID, assigned.Port, len(assigned.Players))
			
			connectToGame(*playerID, assigned)
			break
		}

		queuePos := getQueuePosition(*playerID, status)
		if queuePos > 0 {
			log.Printf("Player %s in queue (position: %d)", *playerID, queuePos)
		}
		time.Sleep(2 * time.Second)
	}
}

func enqueuePlayer(player Player, coordinatorURL string) error {
	jsonData, err := json.Marshal(player)
	if err != nil {
		return err
	}

	resp, err := http.Post(coordinatorURL+"/enqueue", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func getStatus(coordinatorURL string) (*StatusResponse, error) {
	resp, err := http.Get(coordinatorURL + "/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}

	return &status, nil
}

func checkIfAssigned(playerID string, status *StatusResponse) *GameServer {
	for _, gameServer := range status.GameServersDetail {
		for _, player := range gameServer.Players {
			if player.ID == playerID {
				return &gameServer
			}
		}
	}
	return nil
}

func getQueuePosition(playerID string, status *StatusResponse) int {
	for i, player := range status.PlayerQueue {
		if player.ID == playerID {
			return i + 1
		}
	}
	return -1
}

func connectToGame(playerID string, gameServer *GameServer) {
	gameURL := fmt.Sprintf("http://localhost:%d", gameServer.Port)

	for {
		resp, err := http.Get(gameURL + "/health")
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			break
		}

		time.Sleep(1 * time.Second)
	}

	log.Printf("Player %s joined game %s", playerID, gameServer.ID)
}