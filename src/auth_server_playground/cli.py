import os

from dotenv import load_dotenv

from auth_server_playground import create_app
from auth_server_playground import env_flag


def run():
    """Run the Auth Server Playground."""
    load_dotenv()
    app = create_app()
    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_RUN_PORT", "5000"))
    debug = env_flag("FLASK_DEBUG")
    app.run(host=host, port=port, debug=debug)
