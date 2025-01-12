"""
Configuration manager for the Secure Chat Client
"""

import configparser
import logging
import os
from typing import Tuple


class ConfigManager:
    def __init__(self, config_file: str = 'config.ini'):
        self.config = configparser.ConfigParser()

        # Set default values
        self.config['Server'] = {
            'host': 'localhost',
            'port': '8888'
        }
        self.config['Logging'] = {
            'level': 'INFO',
            'debug_mode': 'False'
        }
        self.config['Client'] = {
            'receive_buffer': '4096'
        }

        # Load configuration file if it exists
        if os.path.exists(config_file):
            self.config.read(config_file)
        else:
            # Create config file with default values
            with open(config_file, 'w') as configfile:
                self.config.write(configfile)

    def get_server_details(self) -> Tuple[str, int]:
        """Get server host and port."""
        host = self.config.get('Server', 'host', fallback='localhost')
        port = self.config.getint('Server', 'port', fallback=8888)
        return host, port

    def setup_logging(self) -> None:
        """Configure logging based on settings."""
        level_str = self.config.get('Logging', 'level', fallback='INFO')
        debug_mode = self.config.getboolean('Logging', 'debug_mode', fallback=False)

        # Map string to logging level
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        level = level_map.get(level_str.upper(), logging.INFO)

        # Configure logging
        logging.basicConfig(
            level=level if debug_mode else logging.WARNING,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )

        # Create logger
        logger = logging.getLogger('SecureChatClient')
        logger.setLevel(level if debug_mode else logging.WARNING)

        # Log startup information if in debug mode
        if debug_mode:
            logger.debug("Logging initialized in debug mode")
            logger.debug(f"Log level set to: {level_str}")

    def get_client_settings(self) -> dict:
        """Get all client-specific settings."""
        return {
            'receive_buffer': self.config.getint('Client', 'receive_buffer', fallback=4096)
        }