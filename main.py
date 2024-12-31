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
            # Test if port is available
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
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
        port = find_available_port()
        logger.info(f"Starting server on port {port}")
        socketio.run(app, host='0.0.0.0', port=port, debug=True)
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        raise
