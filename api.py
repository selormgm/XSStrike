import sys
import os
import io
import json
import copy
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse, unquote

# Change the current working directory to the directory of the script
# to ensure the relative imports work correctly.
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Now, import the core modules from the XSStrike project.
# We will create wrappers around these functions to capture their output.
from core.colors import end, green, yellow, red
import core.config
from core.checker import checker
from core.dom import dom
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.log import setup_logger
from core.requester import requester
from core.utils import getUrl, getParams, getVar, updateVar, reader, converter
from core.wafDetector import wafDetector
from modes.bruteforcer import bruteforcer as original_bruteforcer
from modes.scan import scan as original_scan
from modes.singleFuzz import singleFuzz as original_singleFuzz

# Initialize the Flask app and enable CORS
app = Flask(__name__)
CORS(app)

# The original XSStrike functions print to stdout. We'll capture that output
# to return it in the API response. We also need to mock the logger to prevent
# it from printing to the console and to capture log messages as JSON.

class CaptureLogger:
    """A custom logger to capture log messages instead of printing to the console."""
    def __init__(self):
        self.log_messages = []
        self.original_stdout = sys.stdout

    def _log(self, level, message):
        self.log_messages.append({'level': level, 'message': message})

    def debug(self, msg, *args, **kwargs):
        self._log('DEBUG', msg % args)

    def info(self, msg, *args, **kwargs):
        self._log('INFO', msg % args)

    def run(self, msg, *args, **kwargs):
        self._log('RUN', msg % args)

    def good(self, msg, *args, **kwargs):
        self._log('GOOD', msg % args)

    def error(self, msg, *args, **kwargs):
        self._log('ERROR', msg % args)

    def warning(self, msg, *args, **kwargs):
        self._log('WARNING', msg % args)

    def vuln(self, msg, *args, **kwargs):
        self._log('VULN', msg % args)

    def no_format(self, msg, *args, **kwargs):
        self._log('NO_FORMAT', msg % args)

    def red_line(self, *args, **kwargs):
        pass

    def debug_json(self, *args, **kwargs):
        pass

# Helper function to run a mode and capture its output
def run_mode(mode_func, **kwargs):
    """
    Wrapper to run an XSStrike mode function and capture its log output.
    """
    # Use StringIO to capture the output printed by the original functions
    original_stdout = sys.stdout
    sys.stdout = output = io.StringIO()
    
    # Use a custom logger to capture structured log messages
    logger = CaptureLogger()
    core.log.setup_logger = lambda name: logger

    try:
        # Re-initialize global variables used by XSStrike's core
        core.config.globalVariables = {
            'headers': core.config.headers,
            'checkedScripts': set(),
            'checkedForms': {},
            'definitions': json.loads('\n'.join(reader('db/definitions.json'))),
            'jsonData': False,
            'path': False,
            'blindXSS': False,
            'skipDOM': False,
            'skip': False,
            'delay': kwargs.get('delay', core.config.delay),
            'timeout': kwargs.get('timeout', core.config.timeout)
        }
        
        # Call the original function with the provided arguments
        mode_func(**kwargs)
        
    except SystemExit:
        pass
    finally:
        # Restore original stdout
        sys.stdout = original_stdout

    # Get the logs captured by the custom logger
    logs = logger.log_messages
    
    return logs

# API endpoint for the 'scan' mode
@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    try:
        data = request.get_json()
        target = data.get('url')
        param_data = data.get('data')
        headers = data.get('headers', core.config.headers)
        encoding = data.get('encode', False)
        delay = data.get('delay', core.config.delay)
        timeout = data.get('timeout', core.config.timeout)
        skip_dom = data.get('skip_dom', False)
        skip = data.get('skip', False)
        
        # Capture the logs by calling the wrapper function
        logs = run_mode(original_scan, target=target, paramData=param_data, encoding=encoding, headers=headers, delay=delay, timeout=timeout, skipDOM=skip_dom, skip=skip)
        
        return jsonify({'status': 'success', 'logs': logs})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# API endpoint for the 'fuzz' mode
@app.route('/api/fuzz', methods=['POST'])
def fuzz_endpoint():
    try:
        data = request.get_json()
        target = data.get('url')
        param_data = data.get('data')
        headers = data.get('headers', core.config.headers)
        encoding = data.get('encode', False)
        delay = data.get('delay', core.config.delay)
        timeout = data.get('timeout', core.config.timeout)

        logs = run_mode(original_singleFuzz, target=target, paramData=param_data, encoding=encoding, headers=headers, delay=delay, timeout=timeout)
        
        return jsonify({'status': 'success', 'logs': logs})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# API endpoint for the 'bruteforce' mode
@app.route('/api/bruteforce', methods=['POST'])
def bruteforce_endpoint():
    try:
        data = request.get_json()
        target = data.get('url')
        param_data = data.get('data')
        headers = data.get('headers', core.config.headers)
        encoding = data.get('encode', False)
        delay = data.get('delay', core.config.delay)
        timeout = data.get('timeout', core.config.timeout)
        
        # Load payloads from a file. For this example, we'll use a hardcoded list.
        payload_list = core.config.payloads
        
        logs = run_mode(original_bruteforcer, target=target, paramData=param_data, payloadList=payload_list, encoding=encoding, headers=headers, delay=delay, timeout=timeout)
        
        return jsonify({'status': 'success', 'logs': logs})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    # Make sure we are in the correct directory to find the other files.
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    app.run(debug=True)
