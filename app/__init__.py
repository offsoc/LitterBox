from flask import Flask
import yaml
import os
import logging
from colorama import Fore, Style, init

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'config.yaml')
    with open(config_path, 'r') as config_file:
        return yaml.safe_load(config_file)

def create_app():
    app = Flask(__name__)
    
    # Load configuration from YAML
    config = load_config()
    app.config.update(config)
    app.name = config['application']['name']

    # Create all necessary directories
    paths_to_create = {
        config['utils']['upload_folder'],
        config['utils']['result_folder'],
        config['analysis']['doppelganger']['db']['path'],
        os.path.join(config['analysis']['doppelganger']['db']['path'], config['analysis']['doppelganger']['db']['blender']),
        os.path.join(config['analysis']['doppelganger']['db']['path'], config['analysis']['doppelganger']['db']['fuzzyhash'])
    }

    # Create directories
    for path in paths_to_create:
        os.makedirs(path, exist_ok=True)




    # Register routes
    from app.routes import register_routes
    register_routes(app)
    
    return app

# Initialize colorama for Windows compatibility
init(autoreset=True)

def setup_logging(app):
    """Configure logging with selective colors and avoid duplicate logs."""
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':  # Only configure logging in the main process
        return

    if app.config['DEBUG']:  # Only set debug logging if in debug mode
        log_level = logging.DEBUG

        # Use Flask's default handler
        from flask.logging import default_handler
        app.logger.setLevel(log_level)

        # Define a custom formatter with selective colors
        class ColoredFormatter(logging.Formatter):
            LOG_COLORS = {
                "DEBUG": Fore.CYAN,
                "INFO": Fore.GREEN,
                "WARNING": Fore.YELLOW,
                "ERROR": Fore.RED,
                "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
            }

            def format(self, record):
                log_color = self.LOG_COLORS.get(record.levelname, "")
                levelname_color = f"{log_color}{record.levelname}{Style.RESET_ALL}"
                message = f"{Style.RESET_ALL}{record.msg}"  # Ensure the message remains white
                record.levelname = levelname_color
                record.msg = message
                return super().format(record)

        # Update the default handler's formatter
        formatter = ColoredFormatter('[%(asctime)s - %(name)s] [%(levelname)s] - %(message)s')
        default_handler.setFormatter(formatter)

        app.logger.debug("Debug logging is enabled.")