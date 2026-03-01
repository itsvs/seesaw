package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"sync"
	"time"
)

type Player struct {
	ID       string    `json:"id"`
	JoinTime time.Time `json:"join_time"`
}

type GameServer struct {
	ID        string    `json:"id"`
	Port      int       `json:"port"`
	MaxSize   int       `json:"max_size"`
	Process   *exec.Cmd `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type Coordinator struct {
	playerQueue []Player
	gameServers []GameServer
	mutex       sync.RWMutex
	nextPort    int
	maxGameSize int
}

func NewCoordinator() *Coordinator {
	return &Coordinator{
		playerQueue: make([]Player, 0),
		gameServers: make([]GameServer, 0),
		nextPort:    8001,
		maxGameSize: 10,
	}
}

func (c *Coordinator) enqueuePlayer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var player Player
	if err := json.NewDecoder(r.Body).Decode(&player); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	player.JoinTime = time.Now()

	c.mutex.Lock()
	c.playerQueue = append(c.playerQueue, player)
	log.Printf("Player %s enqueued. Queue size: %d", player.ID, len(c.playerQueue))
	c.mutex.Unlock()

	c.processQueue()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "enqueued", "player_id": player.ID})
}

func (c *Coordinator) processQueue() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if len(c.playerQueue) == 0 {
		return
	}

	// Find an available game or create one if we have enough players
	availableGame := c.findAvailableGame()
	if availableGame == nil {
		// Create new game when we have at least 70% capacity
		minPlayersToStart := int(float64(c.maxGameSize) * 0.7)
		if len(c.playerQueue) >= minPlayersToStart {
			availableGame = c.createNewGameServer()
		} else {
			return
		}
	}

	// Assign players to the game server via API call
	for len(c.playerQueue) > 0 {
		player := c.playerQueue[0]
		c.playerQueue = c.playerQueue[1:]
		
		// Make API call to assign player to game server
		if err := c.assignPlayerToGame(player, availableGame); err != nil {
			log.Printf("Failed to assign player %s to game %s: %v", player.ID, availableGame.ID, err)
			// Put player back in queue
			c.playerQueue = append([]Player{player}, c.playerQueue...)
			break
		}
		
		log.Printf("Assigned player %s to game %s (port %d)", player.ID, availableGame.ID, availableGame.Port)
		
		// Check if game server is now full
		gameStatus, err := c.getGameServerStatus(availableGame)
		if err != nil {
			log.Printf("Failed to get game status for %s: %v", availableGame.ID, err)
			break
		}
		
		if gameStatus.PlayerCount >= availableGame.MaxSize {
			break // Game is full, stop assigning
		}
	}
}

func (c *Coordinator) findAvailableGame() *GameServer {
	for i := range c.gameServers {
		gameServer := &c.gameServers[i]
		
		// Check game server status via API
		status, err := c.getGameServerStatus(gameServer)
		if err != nil {
			log.Printf("Failed to get status for game %s: %v", gameServer.ID, err)
			continue
		}
		
		// Game is available if it's waiting for players and not full
		if status.Status == "waiting_for_players" && status.PlayerCount < gameServer.MaxSize {
			return gameServer
		}
	}
	return nil
}

func (c *Coordinator) createNewGameServer() *GameServer {
	gameID := fmt.Sprintf("game-%d", len(c.gameServers)+1)
	port := c.nextPort
	c.nextPort++

	cmd := exec.Command("go", "run", "../game/main.go", fmt.Sprintf("--port=%d", port), fmt.Sprintf("--id=%s", gameID))
	if err := cmd.Start(); err != nil {
		log.Printf("Failed to start game server: %v", err)
		return nil
	}

	gameServer := GameServer{
		ID:        gameID,
		Port:      port,
		MaxSize:   c.maxGameSize,
		Process:   cmd,
		CreatedAt: time.Now(),
	}

	c.gameServers = append(c.gameServers, gameServer)
	log.Printf("Created new game server %s on port %d", gameID, port)

	time.Sleep(1 * time.Second)

	return &gameServer
}

func (c *Coordinator) getStatus(w http.ResponseWriter, r *http.Request) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Get real-time status from each game server
	gameServerDetails := make([]GameServerStatus, 0)
	for _, gameServer := range c.gameServers {
		if gameStatus, err := c.getGameServerStatus(&gameServer); err == nil {
			gameServerDetails = append(gameServerDetails, *gameStatus)
		} else {
			log.Printf("Failed to get status for game %s: %v", gameServer.ID, err)
		}
	}

	status := map[string]interface{}{
		"queue_size":         len(c.playerQueue),
		"game_servers":       len(c.gameServers),
		"player_queue":       c.playerQueue,
		"game_servers_detail": gameServerDetails,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w)
		if r.Method == "OPTIONS" {
			return
		}
		next.ServeHTTP(w, r)
	}
}

func main() {
	coordinator := NewCoordinator()

	http.HandleFunc("/enqueue", corsMiddleware(coordinator.enqueuePlayer))
	http.HandleFunc("/status", corsMiddleware(coordinator.getStatus))

	log.Println("Coordinator server starting on :8000 with CORS enabled")
	log.Fatal(http.ListenAndServe(":8000", nil))
}

type GameServerStatus struct {
	ID              string    `json:"id"`
	Port            int       `json:"port"`
	Status          string    `json:"status"`
	Players         []Player  `json:"players"`
	PlayerCount     int       `json:"player_count"`
	MaxCapacity     int       `json:"max_capacity"`
	SecondsToStart  *int      `json:"seconds_to_start,omitempty"`
	SecondsRemaining *int     `json:"seconds_remaining,omitempty"`
}

func (c *Coordinator) assignPlayerToGame(player Player, gameServer *GameServer) error {
	assignRequest := map[string]string{
		"player_id": player.ID,
	}
	
	jsonData, err := json.Marshal(assignRequest)
	if err != nil {
		return err
	}
	
	url := fmt.Sprintf("http://localhost:%d/assign", gameServer.Port)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("game server returned status %d", resp.StatusCode)
	}
	
	return nil
}

func (c *Coordinator) getGameServerStatus(gameServer *GameServer) (*GameServerStatus, error) {
	url := fmt.Sprintf("http://localhost:%d/status", gameServer.Port)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var status GameServerStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	
	return &status, nil
}