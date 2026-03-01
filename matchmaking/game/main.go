package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type Player struct {
	ID       string    `json:"id"`
	JoinTime time.Time `json:"join_time"`
}

type GameServer struct {
	ID             string       `json:"id"`
	Port           int          `json:"port"`
	StartTime      time.Time    `json:"start_time"`
	Status         string       `json:"status"`
	Players        []Player     `json:"players"`
	MaxCapacity    int          `json:"max_capacity"`
	mutex          sync.RWMutex `json:"-"`
	startTimer     *time.Timer  `json:"-"`
	timerStartTime time.Time    `json:"-"`
	gameStartTime  time.Time    `json:"-"`
	gameTimer      *time.Timer  `json:"-"`
}

func main() {
	port := flag.Int("port", 8001, "Port to run game server on")
	gameID := flag.String("id", "game-1", "Game server ID")
	flag.Parse()

	server := &GameServer{
		ID:          *gameID,
		Port:        *port,
		StartTime:   time.Now(),
		Status:      "waiting_for_players",
		Players:     make([]Player, 0),
		MaxCapacity: 10,
	}

	log.Printf("Game server %s starting on port %d (ready to accept players)", server.ID, server.Port)

	http.HandleFunc("/health", server.healthCheck)
	http.HandleFunc("/status", server.getStatus)
	http.HandleFunc("/assign", server.handleAssign)
	http.HandleFunc("/join", server.handleJoin)
	http.HandleFunc("/start", server.handleStart)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Game server %s listening on %s", server.ID, addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Game server failed to start: %v", err)
	}
}

func (gs *GameServer) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":  "healthy",
		"game_id": gs.ID,
	}
	json.NewEncoder(w).Encode(response)
}

func (gs *GameServer) getStatus(w http.ResponseWriter, r *http.Request) {
	gs.mutex.RLock()
	defer gs.mutex.RUnlock()

	status := map[string]interface{}{
		"id":           gs.ID,
		"port":         gs.Port,
		"start_time":   gs.StartTime,
		"status":       gs.Status,
		"players":      gs.Players,
		"player_count": len(gs.Players),
		"max_capacity": gs.MaxCapacity,
	}

	// Add timer countdown if timer is active
	if gs.startTimer != nil && !gs.timerStartTime.IsZero() {
		elapsed := time.Since(gs.timerStartTime).Seconds()
		remaining := 30.0 - elapsed
		if remaining > 0 {
			status["seconds_to_start"] = int(remaining)
		} else {
			status["seconds_to_start"] = 0
		}
	}

	// Add game time remaining if game is started
	if gs.Status == "started" && !gs.gameStartTime.IsZero() {
		elapsed := time.Since(gs.gameStartTime).Seconds()
		remaining := 120.0 - elapsed // 2 minutes = 120 seconds
		if remaining > 0 {
			status["seconds_remaining"] = int(remaining)
		} else {
			status["seconds_remaining"] = 0
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (gs *GameServer) handleAssign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var assignRequest struct {
		PlayerID string `json:"player_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&assignRequest); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	if gs.Status == "started" {
		http.Error(w, "Game already started", http.StatusConflict)
		return
	}

	// Add player to the game
	player := Player{
		ID:       assignRequest.PlayerID,
		JoinTime: time.Now(),
	}
	gs.Players = append(gs.Players, player)
	playerCount := len(gs.Players)

	log.Printf("Player %s assigned to game %s (%d/%d players)", player.ID, gs.ID, playerCount, gs.MaxCapacity)

	// Check timing thresholds
	gs.checkGameStartConditions()

	response := map[string]interface{}{
		"status":       "assigned",
		"game_id":      gs.ID,
		"player_id":    player.ID,
		"player_count": playerCount,
		"max_capacity": gs.MaxCapacity,
		"game_status":  gs.Status,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (gs *GameServer) handleJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var joinRequest struct {
		PlayerID string `json:"player_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&joinRequest); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	gs.mutex.RLock()
	gameStatus := gs.Status
	playerCount := len(gs.Players)
	gs.mutex.RUnlock()

	if gameStatus == "started" {
		http.Error(w, "Game already started", http.StatusConflict)
		return
	}

	response := map[string]interface{}{
		"status":       "joined",
		"game_id":      gs.ID,
		"player_id":    joinRequest.PlayerID,
		"message":      fmt.Sprintf("Welcome to game %s!", gs.ID),
		"player_count": playerCount,
		"max_capacity": gs.MaxCapacity,
		"game_status":  gameStatus,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (gs *GameServer) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if gs.Status == "started" {
		http.Error(w, "Game already started", http.StatusConflict)
		return
	}

	gs.mutex.Lock()
	gs.Status = "started"
	playerCount := len(gs.Players)
	gs.mutex.Unlock()

	log.Printf("Game %s started with %d/%d players", gs.ID, playerCount, gs.MaxCapacity)

	response := map[string]interface{}{
		"status":       "started",
		"game_id":      gs.ID,
		"player_count": playerCount,
		"max_capacity": gs.MaxCapacity,
		"message":      "Game has started!",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (gs *GameServer) checkGameStartConditions() {
	playerCount := len(gs.Players)

	// Check if game reached 90% capacity and needs a timer
	if gs.Status == "waiting_for_players" && gs.startTimer == nil {
		minPlayersFor90Percent := int(float64(gs.MaxCapacity) * 0.9)
		if playerCount >= minPlayersFor90Percent {
			log.Printf("Game %s reached 90%% capacity (%d/%d players), starting 30s timer",
				gs.ID, playerCount, gs.MaxCapacity)
			gs.timerStartTime = time.Now()
			gs.startTimer = time.AfterFunc(30*time.Second, func() {
				gs.startGameAfterTimer()
			})
		}
	}

	// Start game immediately if full
	if gs.Status == "waiting_for_players" && playerCount >= gs.MaxCapacity {
		if gs.startTimer != nil {
			gs.startTimer.Stop()
			gs.startTimer = nil
			gs.timerStartTime = time.Time{} // Reset timer start time
		}
		gs.startGameImmediate()
	}
}

func (gs *GameServer) startGameAfterTimer() {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	if gs.Status == "waiting_for_players" {
		gs.Status = "started"
		gs.startTimer = nil
		gs.timerStartTime = time.Time{} // Reset timer start time
		gs.gameStartTime = time.Now()
		gs.startGameTimer()
		log.Printf("Game %s started with %d/%d players after 30s timer",
			gs.ID, len(gs.Players), gs.MaxCapacity)
	}
}

func (gs *GameServer) startGameImmediate() {
	gs.Status = "started"
	gs.gameStartTime = time.Now()
	gs.startGameTimer()
	log.Printf("Game %s started immediately with full capacity (%d/%d players)",
		gs.ID, len(gs.Players), gs.MaxCapacity)
}

func (gs *GameServer) startGameTimer() {
	// Start 2-minute game timer
	gs.gameTimer = time.AfterFunc(120*time.Second, func() {
		gs.endGame()
	})
}

func (gs *GameServer) endGame() {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	log.Printf("Game %s completed after 2 minutes", gs.ID)
	gs.Status = "complete"

	// Clean up timers
	if gs.startTimer != nil {
		gs.startTimer.Stop()
	}
	if gs.gameTimer != nil {
		gs.gameTimer.Stop()
	}
}
