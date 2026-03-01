class MatchmakingGUI {
    constructor() {
        this.coordinatorUrl = 'http://localhost:8000';
        this.autoRefreshInterval = null;
        this.isAutoRefreshEnabled = false;
        this.playerNames = [
            'Alice', 'Bob', 'Charlie', 'Diana', 'Eve', 'Frank', 'Grace', 'Henry',
            'Iris', 'Jack', 'Karen', 'Luke', 'Mary', 'Nick', 'Olivia', 'Paul',
            'Quinn', 'Ruby', 'Sam', 'Tina', 'Uma', 'Victor', 'Wendy', 'Xavier',
            'Yara', 'Zoe', 'Alex', 'Blake', 'Casey', 'Drew', 'Emery', 'Finley'
        ];
        this.usedNames = new Set();
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.checkConnection();
        this.refreshStatus();
    }

    setupEventListeners() {
        // Enter key in player name input
        document.getElementById('playerName').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.enqueuePlayer();
            }
        });
    }

    async checkConnection() {
        try {
            const response = await fetch(`${this.coordinatorUrl}/status`);
            if (response.ok) {
                this.updateConnectionStatus(true);
            } else {
                this.updateConnectionStatus(false);
            }
        } catch (error) {
            this.updateConnectionStatus(false);
        }
    }

    updateConnectionStatus(connected) {
        const statusElement = document.getElementById('connectionStatus');
        if (connected) {
            statusElement.textContent = '🟢 Connected';
            statusElement.style.color = '#48bb78';
        } else {
            statusElement.textContent = '🔴 Disconnected';
            statusElement.style.color = '#f56565';
        }
    }

    async refreshStatus() {
        try {
            const response = await fetch(`${this.coordinatorUrl}/status`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const data = await response.json();
            this.updateUI(data);
            this.updateConnectionStatus(true);
            
            // Update last updated time
            const now = new Date().toLocaleTimeString();
            document.getElementById('lastUpdated').textContent = now;
            
        } catch (error) {
            console.error('Failed to refresh status:', error);
            this.updateConnectionStatus(false);
        }
    }

    updateUI(data) {
        // Update coordinator status
        document.getElementById('queueSize').textContent = data.queue_size || 0;
        document.getElementById('gameCount').textContent = data.game_servers || 0;

        // Update player queue
        this.updatePlayerQueue(data.player_queue || []);

        // Update game servers
        this.updateGameServers(data.game_servers_detail || []);
    }

    updatePlayerQueue(queue) {
        const container = document.getElementById('playerQueue');
        
        if (queue.length === 0) {
            container.innerHTML = '<p class="empty-state">No players in queue</p>';
            return;
        }

        const queueHtml = queue.map((player, index) => {
            const joinTime = new Date(player.join_time).toLocaleTimeString();
            return `
                <div class="queue-item">
                    <div class="player-info">
                        <div class="player-name">${player.id}</div>
                        <div class="join-time">Joined: ${joinTime}</div>
                    </div>
                    <div class="queue-position">#${index + 1}</div>
                </div>
            `;
        }).join('');

        container.innerHTML = queueHtml;
    }

    updateGameServers(servers) {
        const container = document.getElementById('gameServers');
        
        if (servers.length === 0) {
            container.innerHTML = '<p class="empty-state">No game servers running</p>';
            return;
        }

        const serversHtml = servers.map(server => {
            const progressPercent = (server.player_count / server.max_capacity) * 100;
            const statusClass = this.getGameStatusClass(server);
            const statusText = this.getGameStatusText(server);
            
            // Generate player list
            let playersHtml = '';
            if (server.players && server.players.length > 0) {
                const playersList = server.players.map(player => {
                    const joinTime = new Date(player.join_time).toLocaleTimeString();
                    return `
                        <div class="player-item">
                            <span class="player-name">${player.id}</span>
                            <span class="player-join-time">${joinTime}</span>
                        </div>
                    `;
                }).join('');
                
                playersHtml = `
                    <div class="players-section">
                        <div class="players-header">Players (${server.players.length})</div>
                        <div class="players-list">
                            ${playersList}
                        </div>
                    </div>
                `;
            }
            
            let timerHtml = '';
            if (server.status === 'complete') {
                timerHtml = `
                    <div class="complete-badge">
                        <div class="complete-text">✅ Game Completed</div>
                    </div>
                `;
            } else if (server.seconds_to_start !== undefined && server.seconds_to_start > 0) {
                timerHtml = `
                    <div class="timer-countdown">
                        <div class="countdown-text">⏰ Starting in ${server.seconds_to_start}s</div>
                    </div>
                `;
            } else if (server.seconds_remaining !== undefined && server.seconds_remaining > 0) {
                const minutes = Math.floor(server.seconds_remaining / 60);
                const seconds = server.seconds_remaining % 60;
                const timeDisplay = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
                timerHtml = `
                    <div class="game-countdown">
                        <div class="countdown-text">🎮 Game ends in ${timeDisplay}</div>
                    </div>
                `;
            }

            return `
                <div class="game-card ${statusClass}">
                    <div class="game-header">
                        <div class="game-id">${server.id}</div>
                        <div class="game-status ${statusClass}">${statusText}</div>
                    </div>
                    
                    <div class="game-details">
                        <div class="detail-item">
                            <div class="detail-label">Port</div>
                            <div class="detail-value">${server.port}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Players</div>
                            <div class="detail-value">${server.player_count}/${server.max_capacity}</div>
                        </div>
                    </div>
                    
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${progressPercent}%"></div>
                    </div>
                    
                    <div style="text-align: center; font-size: 12px; color: #718096; margin-top: 4px;">
                        ${progressPercent.toFixed(0)}% filled
                    </div>
                    
                    ${playersHtml}
                    ${timerHtml}
                </div>
            `;
        }).join('');

        container.innerHTML = serversHtml;
    }

    getGameStatusClass(server) {
        if (server.status === 'complete') return 'complete';
        if (server.status === 'started') return 'started';
        if (server.seconds_to_start !== undefined && server.seconds_to_start > 0) return 'starting';
        return 'waiting';
    }

    getGameStatusText(server) {
        if (server.status === 'complete') return 'Complete';
        if (server.status === 'started') {
            if (server.seconds_remaining !== undefined && server.seconds_remaining > 0) {
                return `Started (${server.seconds_remaining}s left)`;
            }
            return 'Started';
        }
        if (server.seconds_to_start !== undefined && server.seconds_to_start > 0) {
            return `Waiting (${server.seconds_to_start}s)`;
        }
        return 'Waiting';
    }

    async enqueuePlayer() {
        const playerNameInput = document.getElementById('playerName');
        const playerName = playerNameInput.value.trim();
        
        if (!playerName) {
            alert('Please enter a player name');
            return;
        }

        try {
            const response = await fetch(`${this.coordinatorUrl}/enqueue`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    id: playerName,
                    join_time: new Date().toISOString()
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            playerNameInput.value = '';
            this.refreshStatus();
            
        } catch (error) {
            console.error('Failed to enqueue player:', error);
            alert('Failed to enqueue player. Make sure the coordinator is running.');
        }
    }

    async enqueueRandomPlayer() {
        const availableNames = this.playerNames.filter(name => !this.usedNames.has(name));
        
        if (availableNames.length === 0) {
            // Reset if all names used
            this.usedNames.clear();
            availableNames.push(...this.playerNames);
        }
        
        const randomName = availableNames[Math.floor(Math.random() * availableNames.length)];
        this.usedNames.add(randomName);
        
        document.getElementById('playerName').value = randomName;
        await this.enqueuePlayer();
    }

    async enqueueMultiplePlayers(count) {
        const button = event.target;
        button.disabled = true;
        button.textContent = 'Adding...';
        
        try {
            for (let i = 0; i < count; i++) {
                await this.enqueueRandomPlayer();
                // Small delay to see the progression
                await new Promise(resolve => setTimeout(resolve, 200));
            }
        } finally {
            button.disabled = false;
            button.textContent = `Add ${count} Players`;
        }
    }

    async clearQueue() {
        if (!confirm('This will restart the coordinator. Are you sure?')) {
            return;
        }
        
        // For demo purposes, we'll just refresh and show a message
        alert('In a real implementation, this would clear the queue. For now, restart the coordinator manually.');
    }

    async resetDemo() {
        if (!confirm('This will restart the entire demo. Are you sure?')) {
            return;
        }
        
        alert('In a real implementation, this would reset everything. For now, restart the coordinator and game servers manually.');
    }

    toggleAutoRefresh() {
        const button = document.getElementById('autoRefreshBtn');
        const statusElement = document.getElementById('autoRefreshStatus');
        
        if (this.isAutoRefreshEnabled) {
            // Disable auto refresh
            clearInterval(this.autoRefreshInterval);
            this.isAutoRefreshEnabled = false;
            button.textContent = '⏰ Auto Refresh: OFF';
            statusElement.textContent = '';
        } else {
            // Enable auto refresh
            this.autoRefreshInterval = setInterval(() => {
                this.refreshStatus();
            }, 2000); // Refresh every 2 seconds
            
            this.isAutoRefreshEnabled = true;
            button.textContent = '⏰ Auto Refresh: ON';
            statusElement.textContent = 'Auto-refreshing every 2s';
        }
    }
}

// Global functions for HTML onclick handlers
let gui;

function enqueuePlayer() {
    gui.enqueuePlayer();
}

function enqueueRandomPlayer() {
    gui.enqueueRandomPlayer();
}

function enqueueMultiplePlayers(count) {
    gui.enqueueMultiplePlayers(count);
}

function clearQueue() {
    gui.clearQueue();
}

function resetDemo() {
    gui.resetDemo();
}

function refreshStatus() {
    gui.refreshStatus();
}

function toggleAutoRefresh() {
    gui.toggleAutoRefresh();
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', () => {
    gui = new MatchmakingGUI();
});