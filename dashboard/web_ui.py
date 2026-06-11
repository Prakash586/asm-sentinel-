from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from database.db_manager import DatabaseManager
import threading
import time

app = Flask(__name__)
socketio = SocketIO(app)

class Dashboard:
    def __init__(self, db: DatabaseManager):
        self.db = db
        
    def get_stats(self):
        """Get current dashboard statistics"""
        assets = self.db.get_assets()
        
        # Calculate statistics
        total_assets = len(assets)
        live_assets = len([a for a in assets if a.get('status') == 'active'])
        
        # Get recent scans
        recent_scans = self.db.get_recent_scans(limit=30)
        
        return {
            'total_assets': total_assets,
            'live_assets': live_assets,
            'recent_scans': recent_scans,
            'assets': assets
        }

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    stats = dashboard.get_stats()
    return jsonify(stats)

@socketio.on('request_update')
def handle_update():
    """Send real-time updates"""
    stats = dashboard.get_stats()
    emit('stats_update', stats)

def start_dashboard(db: DatabaseManager):
    """Start the web dashboard"""
    global dashboard
    dashboard = Dashboard(db)
    
    print("[+] Starting web dashboard at http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
