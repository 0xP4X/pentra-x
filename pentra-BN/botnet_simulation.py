#!/usr/bin/env python3
"""
Botnet Simulation Tool - Educational/Simulation Purposes Only
A comprehensive botnet simulation system with web UI for educational research.
"""

import os
import json
import time
import threading
import random
import string
import subprocess
import sys
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests

# Check if Flask is installed
try:
    import flask
except ImportError:
    print("[!] Flask not found. Installing...")
    subprocess.run([sys.executable, "-m", "pip", "install", "flask"], capture_output=True)
    import flask

app = Flask(__name__)

# Global bot data
bots = {}
bot_commands = []
bot_stats = {
    'total_bots': 0,
    'active_bots': 0,
    'total_commands': 0,
    'last_activity': None
}

class Bot:
    def __init__(self, bot_id, ip, user_agent, os_info):
        self.bot_id = bot_id
        self.ip = ip
        self.user_agent = user_agent
        self.os_info = os_info
        self.status = 'active'
        self.last_seen = datetime.now()
        self.commands_executed = []
        self.capabilities = {
            'ddos': True,
            'keylogger': True,
            'screenshot': True,
            'file_upload': True,
            'system_info': True
        }

def generate_bot_id():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

@app.route('/')
def dashboard():
    return render_template('dashboard.html', bots=bots, stats=bot_stats, commands=bot_commands)

@app.route('/api/bots')
def get_bots():
    return jsonify(list(bots.values()))

@app.route('/api/bot/register', methods=['POST'])
def register_bot():
    data = request.get_json()
    bot_id = generate_bot_id()
    
    bot = Bot(
        bot_id=bot_id,
        ip=data.get('ip', 'Unknown'),
        user_agent=data.get('user_agent', 'Unknown'),
        os_info=data.get('os_info', 'Unknown')
    )
    
    bots[bot_id] = bot
    bot_stats['total_bots'] = len(bots)
    bot_stats['active_bots'] = len([b for b in bots.values() if b.status == 'active'])
    bot_stats['last_activity'] = datetime.now().isoformat()
    
    return jsonify({'bot_id': bot_id, 'status': 'registered'})

@app.route('/api/bot/<bot_id>/command', methods=['POST'])
def send_command(bot_id):
    if bot_id not in bots:
        return jsonify({'error': 'Bot not found'}), 404
    
    data = request.get_json()
    command = data.get('command', '')
    command_type = data.get('type', 'general')
    
    bot_commands.append({
        'bot_id': bot_id,
        'command': command,
        'type': command_type,
        'timestamp': datetime.now().isoformat(),
        'status': 'pending'
    })
    
    bot_stats['total_commands'] += 1
    
    return jsonify({'status': 'command_sent'})

@app.route('/api/bot/<bot_id>/response', methods=['POST'])
def bot_response(bot_id):
    if bot_id not in bots:
        return jsonify({'error': 'Bot not found'}), 404
    
    data = request.get_json()
    response = data.get('response', '')
    command_id = data.get('command_id', '')
    
    # Update bot last seen
    bots[bot_id].last_seen = datetime.now()
    
    return jsonify({'status': 'response_received'})

@app.route('/api/command/broadcast', methods=['POST'])
def broadcast_command():
    data = request.get_json()
    command = data.get('command', '')
    command_type = data.get('type', 'general')
    
    for bot_id in bots:
        bot_commands.append({
            'bot_id': bot_id,
            'command': command,
            'type': command_type,
            'timestamp': datetime.now().isoformat(),
            'status': 'pending'
        })
    
    bot_stats['total_commands'] += len(bots)
    
    return jsonify({'status': 'broadcast_sent', 'bots_affected': len(bots)})

@app.route('/api/stats')
def get_stats():
    return jsonify(bot_stats)

@app.route('/api/bot/<bot_id>/info')
def get_bot_info(bot_id):
    if bot_id not in bots:
        return jsonify({'error': 'Bot not found'}), 404
    
    bot = bots[bot_id]
    return jsonify({
        'bot_id': bot.bot_id,
        'ip': bot.ip,
        'user_agent': bot.user_agent,
        'os_info': bot.os_info,
        'status': bot.status,
        'last_seen': bot.last_seen.isoformat(),
        'capabilities': bot.capabilities
    })

@app.route('/api/bots/clear', methods=['POST'])
def clear_bots():
    bots.clear()
    bot_commands.clear()
    bot_stats['total_bots'] = 0
    bot_stats['active_bots'] = 0
    bot_stats['total_commands'] = 0
    bot_stats['last_activity'] = None
    return jsonify({'status': 'bots_cleared'})

# Create templates directory
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
os.makedirs(templates_dir, exist_ok=True)

# Create dashboard template
dashboard_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dridex Botnet Control Panel</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        .top-bar {
            background: linear-gradient(90deg, #1a1a1a, #2d2d2d);
            border-bottom: 2px solid #00a8ff;
            padding: 15px 0;
            box-shadow: 0 2px 10px rgba(0, 168, 255, 0.3);
        }
        
        .top-bar-content {
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 20px;
        }
        
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #00a8ff;
            text-shadow: 0 0 10px rgba(0, 168, 255, 0.5);
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #00ff00;
            box-shadow: 0 0 10px #00ff00;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #1a1a1a, #2d2d2d);
            border: 1px solid #333;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 168, 255, 0.2);
            border-color: #00a8ff;
        }
        
        .stat-card h3 {
            font-size: 2.5em;
            color: #00a8ff;
            margin-bottom: 10px;
        }
        
        .stat-card p {
            color: #ccc;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .main-content {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 30px;
        }
        
        .sidebar {
            background: linear-gradient(135deg, #1a1a1a, #2d2d2d);
            border: 1px solid #333;
            border-radius: 8px;
            padding: 20px;
            height: fit-content;
        }
        
        .sidebar h3 {
            color: #00a8ff;
            margin-bottom: 20px;
            border-bottom: 1px solid #333;
            padding-bottom: 10px;
        }
        
        .bot-list {
            max-height: 500px;
            overflow-y: auto;
        }
        
        .bot-item {
            background: rgba(0, 168, 255, 0.05);
            border: 1px solid #333;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .bot-item:hover {
            background: rgba(0, 168, 255, 0.1);
            border-color: #00a8ff;
            transform: translateX(5px);
        }
        
        .bot-item.active {
            background: rgba(0, 168, 255, 0.15);
            border-color: #00a8ff;
            box-shadow: 0 0 15px rgba(0, 168, 255, 0.3);
        }
        
        .bot-id {
            font-weight: bold;
            color: #00a8ff;
            font-size: 14px;
        }
        
        .bot-info {
            font-size: 12px;
            color: #999;
            margin-top: 8px;
            line-height: 1.4;
        }
        
        .main-panel {
            background: linear-gradient(135deg, #1a1a1a, #2d2d2d);
            border: 1px solid #333;
            border-radius: 8px;
            padding: 25px;
        }
        
        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            border-bottom: 1px solid #333;
            padding-bottom: 15px;
        }
        
        .panel-header h2 {
            color: #00a8ff;
            font-size: 20px;
        }
        
        .command-form {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid #333;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 25px;
        }
        
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #00a8ff;
            font-weight: 500;
            font-size: 14px;
        }
        
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 12px;
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #333;
            border-radius: 4px;
            color: #fff;
            font-family: 'Segoe UI', sans-serif;
            font-size: 14px;
        }
        
        .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
            outline: none;
            border-color: #00a8ff;
            box-shadow: 0 0 10px rgba(0, 168, 255, 0.3);
        }
        
        .btn {
            background: linear-gradient(45deg, #00a8ff, #0097e6);
            color: #fff;
            border: none;
            padding: 12px 25px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 1px;
            transition: all 0.3s ease;
            margin-right: 10px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 168, 255, 0.4);
        }
        
        .btn-danger {
            background: linear-gradient(45deg, #e74c3c, #c0392b);
        }
        
        .btn-warning {
            background: linear-gradient(45deg, #f39c12, #e67e22);
        }
        
        .btn-success {
            background: linear-gradient(45deg, #27ae60, #2ecc71);
        }
        
        .command-history {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .command-item {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid #333;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 10px;
            font-size: 13px;
        }
        
        .command-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .command-type {
            background: #00a8ff;
            color: #000;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .command-timestamp {
            color: #999;
            font-size: 11px;
        }
        
        .command-content {
            color: #ccc;
            margin-top: 8px;
            word-break: break-all;
        }
        
        .quick-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .quick-btn {
            background: rgba(0, 168, 255, 0.1);
            border: 1px solid #333;
            color: #00a8ff;
            padding: 10px;
            border-radius: 4px;
            cursor: pointer;
            text-align: center;
            font-size: 12px;
            transition: all 0.3s ease;
        }
        
        .quick-btn:hover {
            background: rgba(0, 168, 255, 0.2);
            border-color: #00a8ff;
        }
        
        .status-badge {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-online {
            background: #00ff00;
            box-shadow: 0 0 8px #00ff00;
        }
        
        .status-offline {
            background: #ff0000;
            box-shadow: 0 0 8px #ff0000;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
        }
        
        .modal-content {
            background: linear-gradient(135deg, #1a1a1a, #2d2d2d);
            margin: 5% auto;
            padding: 30px;
            border: 1px solid #333;
            border-radius: 8px;
            width: 80%;
            max-width: 600px;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            border-bottom: 1px solid #333;
            padding-bottom: 15px;
        }
        
        .close {
            color: #aaa;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: #00a8ff;
        }
        
        .scrollbar::-webkit-scrollbar {
            width: 8px;
        }
        
        .scrollbar::-webkit-scrollbar-track {
            background: #1a1a1a;
        }
        
        .scrollbar::-webkit-scrollbar-thumb {
            background: #333;
            border-radius: 4px;
        }
        
        .scrollbar::-webkit-scrollbar-thumb:hover {
            background: #00a8ff;
        }
    </style>
</head>
<body>
    <div class="top-bar">
        <div class="top-bar-content">
            <div class="logo">DRIDEX CONTROL PANEL</div>
            <div class="status-indicator">
                <div class="status-dot"></div>
                <span>SYSTEM ONLINE</span>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <h3 id="total-bots">0</h3>
                <p>Total Bots</p>
            </div>
            <div class="stat-card">
                <h3 id="active-bots">0</h3>
                <p>Active Bots</p>
            </div>
            <div class="stat-card">
                <h3 id="total-commands">0</h3>
                <p>Commands Sent</p>
            </div>
            <div class="stat-card">
                <h3 id="success-rate">0%</h3>
                <p>Success Rate</p>
            </div>
        </div>
        
        <div class="main-content">
            <div class="sidebar">
                <h3>Connected Bots</h3>
                <div id="bot-list" class="bot-list scrollbar">
                    <p style="text-align: center; color: #999; font-size: 14px;">No bots connected</p>
                </div>
            </div>
            
            <div class="main-panel">
                <div class="panel-header">
                    <h2>Command Center</h2>
                    <div>
                        <button class="btn btn-success" onclick="startBotSimulation()">Start Bot Sim</button>
                        <button class="btn btn-danger" onclick="clearBots()">Clear All</button>
                    </div>
                </div>
                
                <div class="quick-actions">
                    <div class="quick-btn" onclick="quickCommand('ddos', 'SYN Flood Attack')">DDoS Attack</div>
                    <div class="quick-btn" onclick="quickCommand('keylogger', 'Start Keylogger')">Keylogger</div>
                    <div class="quick-btn" onclick="quickCommand('screenshot', 'Take Screenshot')">Screenshot</div>
                    <div class="quick-btn" onclick="quickCommand('system_info', 'Get System Info')">System Info</div>
                    <div class="quick-btn" onclick="quickCommand('file_upload', 'Upload File')">File Upload</div>
                    <div class="quick-btn" onclick="quickCommand('custom', 'Custom Command')">Custom</div>
                </div>
                
                <div class="command-form">
                    <div class="form-row">
                        <div class="form-group">
                            <label for="command-type">Command Type</label>
                            <select id="command-type">
                                <option value="ddos">DDoS Attack</option>
                                <option value="keylogger">Keylogger</option>
                                <option value="screenshot">Screenshot</option>
                                <option value="file_upload">File Upload</option>
                                <option value="system_info">System Info</option>
                                <option value="custom">Custom Command</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="command-target">Target Bot</label>
                            <select id="command-target">
                                <option value="all">All Bots</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="command-input">Command Parameters</label>
                        <textarea id="command-input" rows="4" placeholder="Enter command parameters or target information..."></textarea>
                    </div>
                    
                    <div style="display: flex; gap: 10px;">
                        <button class="btn" onclick="sendCommand()">Execute Command</button>
                        <button class="btn btn-warning" onclick="showAdvancedOptions()">Advanced</button>
                    </div>
                </div>
                
                <div class="panel-header">
                    <h3>Command History</h3>
                    <button class="btn" onclick="clearHistory()">Clear History</button>
                </div>
                
                <div id="command-history" class="command-history scrollbar">
                    <p style="text-align: center; color: #999; font-size: 14px;">No commands sent</p>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Advanced Options Modal -->
    <div id="advancedModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Advanced Command Options</h3>
                <span class="close" onclick="closeAdvancedModal()">&times;</span>
            </div>
            <div class="form-group">
                <label>Execution Delay (seconds)</label>
                <input type="number" id="execution-delay" value="0" min="0" max="3600">
            </div>
            <div class="form-group">
                <label>Retry Count</label>
                <input type="number" id="retry-count" value="1" min="1" max="10">
            </div>
            <div class="form-group">
                <label>Priority Level</label>
                <select id="priority-level">
                    <option value="low">Low</option>
                    <option value="normal" selected>Normal</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                </select>
            </div>
            <button class="btn" onclick="executeAdvancedCommand()">Execute with Options</button>
        </div>
    </div>
    
    <script>
        let selectedBot = null;
        let commandHistory = [];
        
        // Update stats
        function updateStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-bots').textContent = data.total_bots;
                    document.getElementById('active-bots').textContent = data.active_bots;
                    document.getElementById('total-commands').textContent = data.total_commands;
                    
                    // Calculate success rate
                    const successRate = data.total_commands > 0 ? Math.floor(Math.random() * 30) + 70 : 0;
                    document.getElementById('success-rate').textContent = successRate + '%';
                });
        }
        
        // Update bot list
        function updateBotList() {
            fetch('/api/bots')
                .then(response => response.json())
                .then(bots => {
                    const botList = document.getElementById('bot-list');
                    const targetSelect = document.getElementById('command-target');
                    
                    if (bots.length === 0) {
                        botList.innerHTML = '<p style="text-align: center; color: #999; font-size: 14px;">No bots connected</p>';
                        targetSelect.innerHTML = '<option value="all">All Bots</option>';
                        return;
                    }
                    
                    let botListHTML = '';
                    let targetOptions = '<option value="all">All Bots</option>';
                    
                    bots.forEach(bot => {
                        const statusClass = bot.status === 'active' ? 'status-online' : 'status-offline';
                        const lastSeen = new Date(bot.last_seen).toLocaleString();
                        
                        botListHTML += `
                            <div class="bot-item" onclick="selectBot('${bot.bot_id}')">
                                <div class="bot-id">
                                    <span class="status-badge ${statusClass}"></span>
                                    ${bot.bot_id}
                                </div>
                                <div class="bot-info">
                                    IP: ${bot.ip}<br>
                                    OS: ${bot.os_info}<br>
                                    Last Seen: ${lastSeen}
                                </div>
                            </div>
                        `;
                        
                        targetOptions += `<option value="${bot.bot_id}">${bot.bot_id}</option>`;
                    });
                    
                    botList.innerHTML = botListHTML;
                    targetSelect.innerHTML = targetOptions;
                });
        }
        
        // Select bot
        function selectBot(botId) {
            selectedBot = botId;
            document.querySelectorAll('.bot-item').forEach(item => {
                item.classList.remove('active');
            });
            event.target.closest('.bot-item').classList.add('active');
        }
        
        // Quick command
        function quickCommand(type, command) {
            document.getElementById('command-type').value = type;
            document.getElementById('command-input').value = command;
            sendCommand();
        }
        
        // Send command
        function sendCommand() {
            const commandType = document.getElementById('command-type').value;
            const targetBot = document.getElementById('command-target').value;
            const commandInput = document.getElementById('command-input').value;
            
            if (!commandInput.trim()) {
                alert('Please enter command parameters');
                return;
            }
            
            const commandData = {
                command: commandInput,
                type: commandType
            };
            
            const url = targetBot === 'all' ? '/api/command/broadcast' : `/api/bot/${targetBot}/command`;
            
            fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(commandData)
            })
            .then(response => response.json())
            .then(data => {
                if (data.status) {
                    addCommandToHistory(commandType, commandInput, targetBot);
                    updateStats();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error sending command');
            });
        }
        
        // Add command to history
        function addCommandToHistory(type, command, target) {
            const history = document.getElementById('command-history');
            const timestamp = new Date().toLocaleString();
            
            const commandItem = document.createElement('div');
            commandItem.className = 'command-item';
            commandItem.innerHTML = `
                <div class="command-header">
                    <span class="command-type">${type.toUpperCase()}</span>
                    <span class="command-timestamp">${timestamp}</span>
                </div>
                <div class="command-content">
                    <strong>Target:</strong> ${target}<br>
                    <strong>Command:</strong> ${command}
                </div>
            `;
            
            if (history.querySelector('p')) {
                history.innerHTML = '';
            }
            
            history.insertBefore(commandItem, history.firstChild);
            commandHistory.push({type, command, target, timestamp});
        }
        
        // Clear all bots
        function clearBots() {
            if (confirm('Are you sure you want to clear all bots?')) {
                fetch('/api/bots/clear', { method: 'POST' })
                    .then(() => {
                        updateBotList();
                        updateStats();
                    });
            }
        }
        
        // Clear history
        function clearHistory() {
            if (confirm('Clear command history?')) {
                document.getElementById('command-history').innerHTML = '<p style="text-align: center; color: #999; font-size: 14px;">No commands sent</p>';
                commandHistory = [];
            }
        }
        
        // Start bot simulation
        function startBotSimulation() {
            alert('Bot simulation started. Run bot_client.py in separate terminals to add bots.');
        }
        
        // Show advanced options
        function showAdvancedOptions() {
            document.getElementById('advancedModal').style.display = 'block';
        }
        
        // Close advanced modal
        function closeAdvancedModal() {
            document.getElementById('advancedModal').style.display = 'none';
        }
        
        // Execute advanced command
        function executeAdvancedCommand() {
            const delay = document.getElementById('execution-delay').value;
            const retry = document.getElementById('retry-count').value;
            const priority = document.getElementById('priority-level').value;
            
            console.log(`Advanced command with delay: ${delay}s, retry: ${retry}, priority: ${priority}`);
            closeAdvancedModal();
            sendCommand();
        }
        
        // Auto-update every 3 seconds
        setInterval(() => {
            updateStats();
            updateBotList();
        }, 3000);
        
        // Initial load
        updateStats();
        updateBotList();
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('advancedModal');
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        }
    </script>
</body>
</html>'''

# Write dashboard template
with open(os.path.join(templates_dir, "dashboard.html"), "w") as f:
    f.write(dashboard_template)

# Create bot client simulator
bot_client_code = '''#!/usr/bin/env python3
import requests
import time
import random
import string
import json
import threading
from datetime import datetime

class BotClient:
    def __init__(self, server_url="http://localhost:5000"):
        self.server_url = server_url
        self.bot_id = None
        self.running = False
        
        # Simulate different bot characteristics
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15"
        ]
        
        self.os_info = [
            "Windows 10 Pro",
            "Windows 11 Home",
            "macOS 12.0 Monterey",
            "Ubuntu 20.04 LTS",
            "CentOS 7",
            "Debian 11"
        ]
        
        self.ips = [
            "192.168.1.100",
            "192.168.1.101",
            "192.168.1.102",
            "10.0.0.50",
            "172.16.0.25",
            "192.168.0.150"
        ]
    
    def register_bot(self):
        """Register this bot with the server"""
        try:
            data = {
                'ip': random.choice(self.ips),
                'user_agent': random.choice(self.user_agents),
                'os_info': random.choice(self.os_info)
            }
            
            response = requests.post(f"{self.server_url}/api/bot/register", json=data)
            if response.status_code == 200:
                result = response.json()
                self.bot_id = result['bot_id']
                print(f"[+] Bot registered with ID: {self.bot_id}")
                return True
            else:
                print(f"[!] Failed to register bot: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[!] Error registering bot: {e}")
            return False
    
    def simulate_activity(self):
        """Simulate bot activity"""
        while self.running:
            try:
                # Simulate random activities
                activities = [
                    "Browsing web pages",
                    "Downloading files",
                    "Running background processes",
                    "Checking for updates",
                    "Performing system maintenance"
                ]
                
                activity = random.choice(activities)
                print(f"[*] Bot {self.bot_id}: {activity}")
                
                # Random delay between activities
                time.sleep(random.uniform(5, 15))
                
            except Exception as e:
                print(f"[!] Error in bot activity: {e}")
                time.sleep(10)
    
    def start(self):
        """Start the bot client"""
        print("[+] Starting bot client...")
        
        if self.register_bot():
            self.running = True
            
            # Start activity simulation in background
            activity_thread = threading.Thread(target=self.simulate_activity)
            activity_thread.daemon = True
            activity_thread.start()
            
            print(f"[+] Bot {self.bot_id} is now active")
            print("[*] Press Ctrl+C to stop the bot")
            
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\\n[!] Stopping bot...")
                self.running = False

if __name__ == "__main__":
    import sys
    
    server_url = "http://localhost:5000"
    if len(sys.argv) > 1:
        server_url = sys.argv[1]
    
    bot = BotClient(server_url)
    bot.start()
'''

# Write bot client
with open("bot_client.py", "w") as f:
    f.write(bot_client_code)

def main():
    """Main function to start the botnet simulation"""
    print("🤖 Botnet Simulation Tool")
    print("⚠️  This is for educational/simulation purposes only")
    print()
    
    print("Starting botnet simulation server...")
    print("🌐 Dashboard will be available at: http://localhost:5000")
    print("🤖 To start bot clients, run: python bot_client.py")
    print()
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=True)
    except KeyboardInterrupt:
        print("\\n🛑 Server stopped")

if __name__ == '__main__':
    main()