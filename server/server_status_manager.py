from flask import Flask, render_template, current_app
import asyncio

app = Flask(__name__)

@app.route('/')
def server_status(server):
    """
    Displays the status of the secure chat server and connected clients.
    """
    # Fetch the server and client status
    server_running = server.is_running
    connected_clients = len(server.clients)

    # Render the HTML template with the status information
    with current_app.app_context():
        return render_template('server_status.html',
                              server_running=server_running,
                              connected_clients=connected_clients)

def run_status_app(server):
    """
    Start the Flask application in a separate thread.
    """
    app.run(host='localhost', port=8080, debug=True)