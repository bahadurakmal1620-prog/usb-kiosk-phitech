import pyudev
import os
import subprocess
import threading
from scanner import ClamAVEngine, sha256
import database
import app as flask_app

CLEAN_DIR = os.path.expanduser('~/usb-kiosk/clean')
QUARANTINE_DIR = os.path.expanduser('~/usb-kiosk/quarantine')
MOUNT_POINT = '/mnt/usb'

engine = ClamAVEngine()

def get_device_info(device):
    vid = device.get('ID_VENDOR_ID', 'unknown')
    pid = device.get('ID_MODEL_ID', 'unknown')
    serial = device.get('ID_SERIAL_SHORT', 'unknown')
    return f"{vid}:{pid}", serial

def check_bad_usb(device):
    interfaces = device.get('ID_USB_INTERFACES', '')
    if interfaces and '08' not in interfaces:
        return False
    if interfaces and '03' in interfaces and '08' in interfaces:
        return False
    return True

def mount_device(device_node):
    os.makedirs(MOUNT_POINT, exist_ok=True)
    result = subprocess.run(
        ['sudo', 'mount', '-o', 'ro', device_node, MOUNT_POINT],
        capture_output=True
    )
    return result.returncode == 0

def unmount_device():
    subprocess.run(['sudo', 'umount', MOUNT_POINT], capture_output=True)

def process_files(vid_pid, serial):
    flask_app.scan_status['scanning'] = True
    flask_app.scan_status['device'] = vid_pid
    flask_app.scan_status['total'] = 0
    flask_app.scan_status['clean'] = 0
    flask_app.scan_status['threat'] = 0
    flask_app.scan_status['error'] = 0

    files = []
    for root, dirs, filenames in os.walk(MOUNT_POINT):
        for fname in filenames:
            files.append(os.path.join(root, fname))

    flask_app.scan_status['total'] = len(files)

    for filepath in files:
        flask_app.scan_status['current_file'] = filepath
        file_hash = sha256(filepath)
        result = engine.scan(filepath)
        fname = os.path.basename(filepath)

        if result.verdict == 'clean':
            dest = os.path.join(CLEAN_DIR, fname)
            subprocess.run(['cp', filepath, dest])
            action = 'copied to clean'
            flask_app.scan_status['clean'] += 1
        elif result.verdict == 'threat':
            dest = os.path.join(QUARANTINE_DIR, fname)
            subprocess.run(['mv', filepath, dest])
            os.chmod(dest, 0o000)
            action = 'quarantined'
            flask_app.scan_status['threat'] += 1
            flask_app.scan_status['alert'] = True
        else:
            action = 'flagged for review'
            flask_app.scan_status['error'] += 1

        database.log_file_event(
            vid_pid, serial, fname, filepath,
            file_hash, result.engine, result.verdict,
            result.detection or '', action, result.error or ''
        )

    flask_app.scan_status['scanning'] = False
    flask_app.scan_status['current_file'] = 'Scan Complete'

def handle_usb_event(action, device):
    if device.get('ID_TYPE') != 'disk':
        return

    vid_pid, serial = get_device_info(device)

    if action == 'add':
        if not check_bad_usb(device):
            database.log_device_event(vid_pid, serial, 'insertion', 'rejected', 'BadUSB detected')
            return

        device_node = device.get('DEVNAME')
        if not device_node:
            return

        database.log_device_event(vid_pid, serial, 'insertion', 'accepted')

        if mount_device(device_node):
            database.log_device_event(vid_pid, serial, 'mount', 'success')
            t = threading.Thread(target=process_files, args=(vid_pid, serial))
            t.start()
        else:
            database.log_device_event(vid_pid, serial, 'mount', 'failed')

    elif action == 'remove':
        unmount_device()
        database.log_device_event(vid_pid, serial, 'removal', 'unmounted')

def start_monitor():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='block', device_type='disk')
    observer = pyudev.MonitorObserver(monitor, callback=handle_usb_event)
    observer.start()
    print('USB Monitor started...')
    observer.join()

if __name__ == '__main__':
    start_monitor()
