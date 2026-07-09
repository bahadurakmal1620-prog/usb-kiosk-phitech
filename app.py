from flask import Flask, render_template, jsonify, send_file
import database
import os

app = Flask(__name__)
database.init_db()

scan_status = {
    'current_file': '',
    'total': 0,
    'clean': 0,
    'threat': 0,
    'error': 0,
    'device': '',
    'scanning': False,
    'alert': False
}

@app.route('/')
def index():
    return render_template('index.html', status=scan_status)

@app.route('/status')
def status():
    return jsonify(scan_status)

@app.route('/logs')
def logs():
    events = database.get_all_file_events()
    return render_template('logs.html', events=events)

@app.route('/export')
def export():
    path = os.path.expanduser('~/usb-kiosk/logs/audit.csv')
    database.export_csv(path)
    return send_file(path, as_attachment=True)

@app.route('/acknowledge')
def acknowledge():
    scan_status['alert'] = False
    return jsonify({'ok': True})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
