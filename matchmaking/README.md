# Game Matchmaking Demo

A sophisticated demonstration of server-based matchmaking for video games with smart capacity management, timer-based game starting, and automatic game lifecycle management.

## Architecture

### Coordinator (`coordinator/main.go`) - The Middleman
- **Matchmaking server** running on port 8000 with CORS enabled
- **Player queue management** and game server orchestration
- **Smart game creation** at 70% capacity (7/10 players)
- **API-driven communication** with game servers
- **Real-time status** aggregation from all game servers

### Player (`player/main.go`) - The Client
- **Autonomous clients** that connect to coordinator for matchmaking
- **Intelligent polling** until assigned to a game server
- **Automatic connection** to assigned game servers

### Game Server (`game/main.go`) - The Autonomous Game Instance
- **Self-managing** game instances spawned by coordinator
- **Smart timing logic**: 90% capacity triggers 30-second timer
- **Player tracking** with join times and full game state
- **2-minute game duration** with automatic completion
- **API endpoints** for assignment, status, and health checks

## Smart Matchmaking Features

### 🎯 **Capacity-Based Game Creation**
- **70% threshold**: Games created when 7+ players are queued
- **Early start**: Players can join games while waiting for more
- **Dynamic scaling**: Multiple games created as needed

### ⏰ **Intelligent Game Starting**
- **90% capacity**: 30-second timer starts (9/10 players)
- **Timer countdown**: Visible in real-time status
- **100% capacity**: Immediate start (cancels timer)
- **Partial games**: Can start with 9 players after timer

### 🕐 **Complete Game Lifecycle**
- **WAITING** → Accepting players
- **WAITING (15s)** → Timer countdown at 90% capacity  
- **STARTED** → Game in progress
- **STARTED (45s LEFT)** → Time remaining countdown
- **COMPLETE** → Game finished (stays visible)

## Usage Options

### 🖥️ **Interactive GUI** (Recommended)
```bash
# Start coordinator with CORS
cd coordinator && go run main.go

# Open gui/index.html in browser
# Use the interactive interface to add players and watch games
```

### 📜 **Command Line Demo**
```bash
./demo.sh  # Comprehensive demo with 19 players
```

### 🔧 **Manual API Testing**
```bash
# Start coordinator
cd coordinator && go run main.go

# Add players via API
curl -X POST http://localhost:8000/enqueue \
  -H "Content-Type: application/json" \
  -d '{"id": "alice"}'

# Check real-time status
curl http://localhost:8000/status | jq
```

## API Reference

### Coordinator Endpoints (port 8000)
- `POST /enqueue` - Add player to matchmaking queue
  ```json
  {"id": "player_name", "join_time": "2025-01-15T10:30:00Z"}
  ```
- `GET /status` - Complete system status with real-time game data
  ```json
  {
    "queue_size": 2,
    "game_servers": 1,
    "player_queue": [...],
    "game_servers_detail": [...]
  }
  ```

### Game Server Endpoints (ports 8001+)
- `GET /health` - Health check
- `GET /status` - Detailed game status with players and timers
- `POST /assign` - Assign player to game (used by coordinator)
- `POST /join` - Manual player join
- `POST /start` - Force game start

## Demo Scenarios

### 🎮 **GUI Interactive Demo**
1. **Add 7 players** → Watch first game create at 70% capacity
2. **Add 2 more players** → See 90% timer start (30s countdown)
3. **Wait or add 10th** → Game starts (timer expires or 100% reached)
4. **Add more players** → Second game creates and cycles repeat
5. **Watch 2-minute games** → Games complete and show purple COMPLETE status

### 📊 **Command Line Demo Flow**
- **Phase 1**: 7 players → Game creation
- **Phase 2**: 9 players → Timer activation  
- **Phase 3**: 10 players → Immediate start
- **Phase 4**: 19 total players → Multiple games with different states

## Technical Details

### Configuration
- **Max game size**: 10 players
- **Creation threshold**: 70% (7 players)
- **Timer threshold**: 90% (9 players)
- **Timer duration**: 30 seconds
- **Game duration**: 2 minutes
- **Coordinator port**: 8000
- **Game server ports**: 8001, 8002, 8003...

### Process Management
- **Child processes**: Game servers are spawned as coordinator children
- **Automatic cleanup**: Killing coordinator terminates all game servers
- **No zombies**: Clean resource management
- **Graceful completion**: Games finish naturally without self-termination

### Real-time Features
- **Live status updates**: All timing and player data
- **Timer countdowns**: Both start timers and game duration
- **Player tracking**: Join times and game assignments
- **Visual indicators**: Color-coded game states in GUI