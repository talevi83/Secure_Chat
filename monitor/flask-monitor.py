from flask import Flask, render_template
import requests
from requests.exceptions import RequestException
import logging
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get API URL from environment variable or use default
API_BASE_URL = os.environ.get('API_BASE_URL', 'http://chat-server:8000')


def get_server_status():
    """
    Fetch server status from the API
    """
    try:
        response = requests.get(f'{API_BASE_URL}/api/status', timeout=5)
        response.raise_for_status()
        return response.json()
    except RequestException as e:
        logger.error(f"Failed to fetch server status: {e}")
        return None


@app.route('/')
def server_status():
    """
    Displays the status of the secure chat server and connected clients.
    """
    status = get_server_status()

    if status is None:
        return render_template('server_status.html',
                               server_running=False,
                               connected_clients=0,
                               error_message="Unable to connect to chat server")

    return render_template('server_status.html',
                           server_running=status['server_running'],
                           connected_clients=status['connected_clients'],
                           connected_users=status.get('connected_users', []))


def run_monitor_app():
    """
    Start the Flask monitoring application
    """
    app.run(host='0.0.0.0', port=8080, debug=False)


if __name__ == '__main__':
    run_monitor_app()