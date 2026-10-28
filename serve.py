"""Run the local Flask application with the Waitress WSGI server."""
from waitress import serve

from app import app


if __name__ == "__main__":
    serve(app, host="127.0.0.1", port=5000, threads=8)
