from flask import Flask, render_template, current_app
import asyncio

app = Flask(__name__)

# Store server instance
chat_server = None

def init_app(server):
    """Initialize the Flask app with server instance"""
    global chat_server
    chat_server = server

@app.route('/')
def server_status():
    """
    Displays the status of the secure chat server and connected clients.
    """
    global chat_server
    if not chat_server:
        return "Server not initialized", 500

    # Fetch the server and client status
    server_running = chat_server.is_running
    connected_clients = len(chat_server.clients)

    # Render the HTML template with the status information
    return render_template('server_status.html',
                         server_running=server_running,
                         connected_clients=connected_clients)

def run_status_app():
    """
    Start the Flask application in a separate thread.
    """
    app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)