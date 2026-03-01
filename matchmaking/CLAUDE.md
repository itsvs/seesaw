# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a sophisticated game matchmaking system demonstration with three main components that communicate via HTTP APIs. The system showcases intelligent capacity-based game creation, timer-driven game starting, and complete game lifecycle management.

## Architecture

### Coordinator-Centric Design
The **coordinator** (`coordinator/main.go`) acts as the central orchestrator that:
- Manages a global player queue
- Spawns game server processes as child processes using `exec.Command`
- Communicates with game servers via HTTP APIs (not direct state sharing)
- Aggregates real-time status from all game servers
- Implements smart game creation at 70% capacity threshold (7/10 players)

### Game Server Autonomy
Each **game server** (`game/main.go`) is fully autonomous and:
- Manages its own player list and game state
- Implements complex timing logic (90% capacity → 30s timer, 100% → immediate start)
- Runs 2-minute games that auto-complete to "complete" status
- Exposes `/assign`, `/status`, `/health` endpoints
- Handles player assignment requests from coordinator

### Player Simulation
The **player** (`player/main.go`) simulates game clients that:
- Enqueue via coordinator API
- Poll for game assignments
- Connect to assigned game servers
- Provide realistic matchmaking load testing

## Key Development Commands

### Starting the System
```bash
# Start coordinator (required first)
cd coordinator && go run main.go

# Interactive GUI (recommended)
open gui/index.html

# Command line demo
./demo.sh

# Manual player testing
cd player && go run main.go -id="player_name"
```

### Development Workflow
```bash
# Test coordinator API
curl -X POST http://localhost:8000/enqueue -H "Content-Type: application/json" -d '{"id": "test_player"}'
curl http://localhost:8000/status | jq

# Test game server directly
curl http://localhost:8001/status | jq
curl http://localhost:8001/health
```

## Critical System Behaviors

### Process Management
- Coordinator spawns game servers as child processes
- Killing coordinator automatically terminates all game servers (no cleanup needed)
- Game servers DO NOT self-terminate - they set status to "complete" after 2 minutes

### Timing Logic
- **70% capacity (7 players)**: Coordinator creates new game server
- **90% capacity (9 players)**: Game server starts 30-second countdown timer
- **100% capacity (10 players)**: Game starts immediately (cancels timer)
- **2-minute duration**: Games auto-complete but continue running

### State Synchronization
- Coordinator maintains GameServer structs with minimal metadata (ID, Port, MaxSize, Process)
- Game servers maintain full game state (Players, Status, Timers)
- Real-time status aggregated via HTTP calls from coordinator to game servers
- No shared memory or direct state between coordinator and game servers

## API Communication Patterns

### Coordinator ↔ Game Server
```go
// Coordinator assigns players via POST /assign
POST http://localhost:8001/assign
{"player_id": "alice"}

// Coordinator fetches status via GET /status  
GET http://localhost:8001/status
// Returns: players, status, timers, capacity, etc.
```

### Client ↔ Coordinator
```go
// Players enqueue via POST /enqueue
POST http://localhost:8000/enqueue
{"id": "player_name", "join_time": "..."}

// GUI polls GET /status for real-time updates
GET http://localhost:8000/status
// Returns: queue, aggregated game server details
```

## Configuration Constants

- **Max game size**: 10 players
- **Game creation threshold**: 70% (7 players)
- **Timer trigger threshold**: 90% (9 players)
- **Start timer duration**: 30 seconds
- **Game duration**: 2 minutes (120 seconds)
- **Coordinator port**: 8000
- **Game server ports**: 8001, 8002, 8003... (auto-increment)

## GUI Integration

The GUI (`gui/`) provides a production-ready web interface with:
- CORS-enabled coordinator communication
- Real-time status updates every 2 seconds
- Player list management with join times
- Visual game state indicators (WAITING → STARTED → COMPLETE)
- Timer countdowns for both game start and game duration

## Common Pitfalls

1. **Start coordinator first** - Game servers are spawned by coordinator, not standalone
2. **CORS required** - GUI needs coordinator with CORS headers enabled
3. **Process dependencies** - Game servers die when coordinator dies (expected behavior)
4. **Timer vs Status** - Game servers handle all timing logic, coordinator just aggregates
5. **API-driven state** - No direct memory sharing between components