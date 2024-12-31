from app import app, db, socketio
import socket
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def find_available_port(start_port=5000, max_attempts=10):
    """Find an available port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        try:
            # Create a socket to test if port is available
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set SO_REUSEADDR option to allow port reuse
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Attempt to bind to the port
            sock.bind(('0.0.0.0', port))
            sock.listen(1)  # Test if we can listen on the port
            sock.close()
            logger.info(f"Found available port: {port}")
            return port
        except OSError as e:
            logger.debug(f"Port {port} is in use, trying next port: {str(e)}")
            continue

    error_msg = f"Could not find an available port in range {start_port}-{start_port + max_attempts}"
    logger.error(error_msg)
    raise RuntimeError(error_msg)

if __name__ == "__main__":
    with app.app_context():
        # Create database tables
        db.create_all()
        logger.info("Database tables created successfully")

    try:
        # Find an available port and start the server
        port = find_available_port()
        logger.info(f"Starting server on port {port}")
        socketio.run(
            app,
            host='0.0.0.0',
            port=port,
            debug=True,
            allow_unsafe_werkzeug=True,
            use_reloader=True,
            log_output=True
        )
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        raise