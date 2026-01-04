"""
Flask Web Dashboard for IDS
"""
from flask import Flask, render_template, jsonify
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from ids.ids_engine import IDSEngine
from ids.core.config import config

app = Flask(__name__)

# Global IDS engine instance (will be set from main)
ids_engine = None

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get current IDS statistics."""
    if ids_engine:
        stats = ids_engine.get_statistics()
        return jsonify(stats)
    
    return jsonify({
        'engine': {'packets_processed': 0, 'anomalies_detected': 0, 'alerts_generated': 0},
        'anomaly_detector': {'total_ips': 0, 'total_anomalies': 0},
        'rule_detector': {'total_alerts': 0},
        'alert_manager': {'total_alerts': 0, 'by_severity': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}}
    })

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts."""
    if ids_engine:
        alert_stats = ids_engine.alert_manager.get_statistics()
        return jsonify(alert_stats.get('recent_alerts', []))
    
    return jsonify([])

@app.route('/api/anomalies')
def get_anomalies():
    """Get recent anomalies."""
    if ids_engine:
        anomaly_stats = ids_engine.anomaly_detector.get_statistics()
        return jsonify(anomaly_stats.get('recent_anomalies', []))
    
    return jsonify([])

def run_dashboard(engine):
    """Run the dashboard server."""
    global ids_engine
    ids_engine = engine
    
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=False,
        use_reloader=False
    )