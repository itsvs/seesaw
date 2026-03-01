#!/bin/bash

# Demo script for matchmaking system
# This script demonstrates the matchmaking flow by:
# 1. Starting the coordinator server
# 2. Simulating multiple players joining the queue
# 3. Showing how game servers are automatically spawned

echo "🎮 Starting Matchmaking Demo"
echo "================================"

# Function to cleanup processes on exit
cleanup() {
    echo "🛑 Cleaning up processes..."
    pkill -f "coordinator/main.go"
    pkill -f "game/main.go"
    pkill -f "player/main.go"
    exit 0
}

# Set trap to cleanup on script exit
trap cleanup EXIT

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Start coordinator server in background
echo "🔧 Starting coordinator server..."
(cd "$SCRIPT_DIR/coordinator" && go run main.go) &
COORDINATOR_PID=$!

# Wait for coordinator to start
sleep 2

echo "✅ Coordinator server started (PID: $COORDINATOR_PID)"
echo ""

# Function to start a player
start_player() {
    local player_id=$1
    echo "👤 Starting player: $player_id"
    (cd "$SCRIPT_DIR/player" && go run main.go -id="$player_id") &
}

# Function to check coordinator status
check_status() {
    echo "📊 Coordinator Status:"
    curl -s http://localhost:8000/status | jq '.'
    echo ""
}

echo "📊 Initial coordinator status:"
check_status

echo "🚀 Starting demo with new timing logic (max size: 10):"
echo "   - Games start at 70% capacity (7/10 players)"
echo "   - At 90% capacity (9/10 players), 30s timer starts"
echo "   - At 100% capacity (10/10 players), game starts immediately"
echo ""

echo "Phase 1: Testing 70% threshold (7 players)"
echo "=========================================="

# Add players one by one until we hit 70%
for i in {1..7}; do
    names=("alice" "bob" "charlie" "diana" "eve" "frank" "grace")
    start_player "${names[$i-1]}"
    sleep 0.5
done

sleep 2
echo "📊 Status after 7 players (should have created game at 70% capacity):"
check_status

echo ""
echo "Phase 2: Testing 90% threshold (9 players)"
echo "=========================================="

start_player "henry"
sleep 0.5
start_player "iris"
sleep 2

echo "📊 Status after 9 players (should show 90% timer started):"
check_status

echo ""
echo "Phase 3: Testing timer vs immediate start"
echo "========================================"

echo "🔀 Choose your adventure:"
echo "   A) Wait 35s to see timer finish"
echo "   B) Add 10th player to trigger immediate start"
echo ""
echo "🤖 Auto-choosing B for demo..."

start_player "jack"
sleep 2

echo "📊 Status after 10 players (should have started immediately):"
check_status

echo ""
echo "Phase 4: Testing second game creation"
echo "===================================="

echo "🔄 Adding players for second game..."
for i in {11..17}; do
    names=("karen" "luke" "mary" "nick" "olivia" "paul" "quinn")
    start_player "${names[$i-11]}"
    sleep 0.3
done

sleep 2
echo "📊 Status after 7 players (should show second game created):"
check_status

echo ""
echo "🎯 Adding 2 more players to trigger 90% timer..."
start_player "ruby"
sleep 0.5
start_player "sam"
sleep 2

echo "📊 Status with 9 players (should show timer countdown):"
check_status

echo ""
echo "⏱️  Watching timer countdown for 10 seconds..."
for i in {1..5}; do
    sleep 2
    echo "📊 Timer status check $i:"
    check_status
done

echo ""
echo "📊 Final status:"
check_status

echo "🎉 Demo complete! Game servers should be running on ports 8001 and 8002"
echo "💡 You can check game server status with:"
echo "   curl http://localhost:8001/status"
echo "   curl http://localhost:8002/status"
echo ""
echo "Press Ctrl+C to stop all servers"

# Keep script running until user interrupts
while true; do
    sleep 5
    echo "⏰ $(date): Demo still running..."
done