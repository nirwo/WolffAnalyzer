from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, session
import os
import re
import json
import uuid
import hashlib
import requests
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import logging
from functools import wraps
from collections import defaultdict
import difflib

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size
app.config['PATTERNS_FILE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'patterns.json')
app.config['KPI_FILE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'error_kpi.json')
app.config['USERS_FILE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.json')
app.config['SETTINGS_FILE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'settings.json')
app.config['SESSION_LIFETIME'] = timedelta(hours=24)  # Set session timeout to 24 hours

# User roles
ROLE_ADMIN = 'admin'
ROLE_USER = 'user'

# Create logs directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Add Jinja2 filters or globals
app.jinja_env.globals.update(enumerate=enumerate)

# Initialize users database if it doesn't exist
if not os.path.exists(app.config['USERS_FILE']):
    with open(app.config['USERS_FILE'], 'w') as f:
        # Create default admin user
        admin_password = 'admin123'  # This is just for demo, in production use a strong password
        admin_password_hash = hashlib.sha256(admin_password.encode()).hexdigest()
        
        # Use a static ID for admin for easy reference
        admin_id = '00000000-0000-0000-0000-000000000000'
        
        json.dump({
            'users': [
                {
                    'id': admin_id,
                    'username': 'admin',
                    'password_hash': admin_password_hash,
                    'role': ROLE_ADMIN,
                    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'logs': []
                }
            ]
        }, f, indent=2)

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function
def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page')
            return redirect(url_for('login', next=request.url))
        
        # Check if user is admin
        try:
            with open(app.config['USERS_FILE'], 'r') as file_handle:
                users_data = json.load(file_handle)
                
            user = next((u for u in users_data['users'] if u['id'] == session['user_id']), None)
            if not user or user['role'] != ROLE_ADMIN:
                flash('You do not have permission to access this page')
                return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error checking user permissions: {str(e)}')
            return redirect(url_for('index'))
            
        return func(*args, **kwargs)
    return decorated_function

# Initialize patterns database if it doesn't exist
if not os.path.exists(app.config['PATTERNS_FILE']):
    with open(app.config['PATTERNS_FILE'], 'w') as f:
        json.dump({
            'jenkins_patterns': [
                {
                    'id': 1,
                    'name': 'Maven Build Error',
                    'pattern': r'BUILD FAILURE|Failed to execute goal',
                    'severity': 'critical',
                    'description': 'Maven build process failed',
                    'suggestion': 'Check for compilation errors, dependency issues, or test failures'
                },
                {
                    'id': 2,
                    'name': 'NPM Error',
                    'pattern': r'npm ERR!',
                    'severity': 'critical',
                    'description': 'NPM package or build error',
                    'suggestion': 'Verify package.json, dependencies, or build scripts'
                },
                {
                    'id': 3,
                    'name': 'Missing Dependency',
                    'pattern': r'Cannot find module|Could not find|No such file or directory',
                    'severity': 'error',
                    'description': 'Required dependency or file is missing',
                    'suggestion': 'Install missing dependencies or check file paths'
                },
                {
                    'id': 4,
                    'name': 'Permission Error',
                    'pattern': r'Permission denied|EACCES',
                    'severity': 'error',
                    'description': 'Insufficient permissions to access a resource',
                    'suggestion': 'Check file/directory permissions or use sudo/admin privileges'
                },
                {
                    'id': 5,
                    'name': 'Test Failure',
                    'pattern': r'Tests failed|Test failures|FAILED TEST',
                    'severity': 'warning',
                    'description': 'One or more tests are failing',
                    'suggestion': 'Check test output and fix failing tests'
                },
                {
                    'id': 8,
                    'name': 'Compilation Error',
                    'pattern': r'Compilation failed|compiler error|compilation error|error: \[|javac',
                    'severity': 'critical',
                    'description': 'Java compilation error',
                    'suggestion': 'Check for syntax errors, missing imports, or incorrect code'
                },
                {
                    'id': 9,
                    'name': 'Gradle Error',
                    'pattern': r'FAILURE: Build failed with an exception|Execution failed for task|Gradle build daemon disappeared',
                    'severity': 'critical',
                    'description': 'Gradle build process failed',
                    'suggestion': 'Check build.gradle files and task configuration'
                },
                {
                    'id': 10,
                    'name': 'Docker Build Failure',
                    'pattern': r'docker build.*failed|The command.*returned a non-zero code',
                    'severity': 'critical',
                    'description': 'Docker image build failed',
                    'suggestion': 'Check Dockerfile syntax and build commands'
                },
                {
                    'id': 11,
                    'name': 'Linting Error',
                    'pattern': r'ESLint|lint task|checkstyle|pylint|rubocop',
                    'severity': 'warning',
                    'description': 'Code style or linting errors',
                    'suggestion': 'Fix code style issues according to project standards'
                },
                {
                    'id': 12,
                    'name': 'Missing Credentials',
                    'pattern': r'authentication failed|credentials.*not found|no credentials|not authorized|permission denied',
                    'severity': 'error',
                    'description': 'Missing or invalid credentials',
                    'suggestion': 'Check Jenkins credentials configuration or secrets management'
                }
            ],
            'system_patterns': [
                {
                    'id': 6,
                    'name': 'Out of Memory',
                    'pattern': r'OutOfMemoryError|MemoryError|out of memory|insufficient memory|Java heap space',
                    'severity': 'critical',
                    'description': 'Process ran out of memory',
                    'suggestion': 'Increase memory allocation or optimize memory usage'
                },
                {
                    'id': 7,
                    'name': 'Connection Error',
                    'pattern': r'Connection refused|Connection reset|Connection timeout|connect: Network is unreachable',
                    'severity': 'error',
                    'description': 'Network connection problem',
                    'suggestion': 'Check network connectivity, firewall rules, or service availability'
                },
                {
                    'id': 13,
                    'name': 'Disk Space Error',
                    'pattern': r'No space left on device|disk full|insufficient disk|not enough space',
                    'severity': 'critical',
                    'description': 'Disk space is exhausted',
                    'suggestion': 'Clean up disk space or increase storage allocation'
                },
                {
                    'id': 14,
                    'name': 'Timeout Error',
                    'pattern': r'timed out|timeout|time limit exceeded|took too long',
                    'severity': 'error',
                    'description': 'Operation exceeded the time limit',
                    'suggestion': 'Increase timeout thresholds or optimize the operation'
                },
                {
                    'id': 15,
                    'name': 'Version Mismatch',
                    'pattern': r'version mismatch|incompatible version|requires version|expected version',
                    'severity': 'error',
                    'description': 'Incompatible software versions',
                    'suggestion': 'Align software versions or update dependencies'
                },
                {
                    'id': 16,
                    'name': 'Database Error',
                    'pattern': r'database error|sql error|database connection|sql exception|deadlock|lock wait timeout',
                    'severity': 'critical',
                    'description': 'Database-related error',
                    'suggestion': 'Check database configuration, queries, or connection parameters'
                },
                {
                    'id': 17,
                    'name': 'SSL/TLS Error',
                    'pattern': r'SSL handshake|certificate verify|certificate error|untrusted certificate',
                    'severity': 'error',
                    'description': 'SSL/TLS connection issues',
                    'suggestion': 'Check certificates, TLS version, or security configuration'
                }
            ]
        }, f, indent=2)

# Initialize KPI database if it doesn't exist
if not os.path.exists(app.config['KPI_FILE']):
    with open(app.config['KPI_FILE'], 'w') as f:
        json.dump({
            'error_occurrences': {},
            'common_patterns': {},
            'related_errors': {},
            'total_logs_analyzed': 0,
            'errors_by_date': {}
        }, f, indent=2)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Error levels and their severity
ERROR_LEVELS = {
    'ERROR': 3,
    'CRITICAL': 4, 
    'FATAL': 4,
    'EXCEPTION': 3,
    'WARNING': 2,
    'WARN': 2,
    'INFO': 1,
    'DEBUG': 0
}

def allowed_file(filename):
    """Check if the uploaded file is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'log', 'txt'}

def load_patterns():
    """Load error patterns from database"""
    with open(app.config['PATTERNS_FILE'], 'r') as f:
        return json.load(f)

def update_error_kpi(error_type, log_source='unknown'):
    """Update error KPI statistics"""
    try:
        # Load current KPI data
        with open(app.config['KPI_FILE'], 'r') as f:
            kpi_data = json.load(f)
        
        # Update error occurrences
        if error_type not in kpi_data['error_occurrences']:
            kpi_data['error_occurrences'][error_type] = 0
        kpi_data['error_occurrences'][error_type] += 1
        
        # Update total logs analyzed
        kpi_data['total_logs_analyzed'] += 1
        
        # Update errors by date
        today = datetime.now().strftime('%Y-%m-%d')
        if today not in kpi_data['errors_by_date']:
            kpi_data['errors_by_date'][today] = {}
        if error_type not in kpi_data['errors_by_date'][today]:
            kpi_data['errors_by_date'][today][error_type] = 0
        kpi_data['errors_by_date'][today][error_type] += 1
        
        # Save updated KPI data
        with open(app.config['KPI_FILE'], 'w') as f:
            json.dump(kpi_data, f, indent=2)
    except Exception as e:
        logger.warning(f"Failed to update KPI data: {str(e)}")

def parse_log(log_content):
    """Parse log content and extract entries with timestamps, components, and error levels"""
    entries = []
    
    # Pre-process the content to remove HTML timestamp spans and other HTML tags
    # This will clean the actual content and prevent the span tags from appearing in the output
    log_content = re.sub(r'<span class="timestamp"><b>(\d{2}:\d{2}:\d{2})</b></span>', r'[\1]', log_content)
    log_content = re.sub(r'<[^>]+>', '', log_content)
    
    # Split the log content into lines
    lines = log_content.strip().split('\n')
    
    # Common timestamp patterns in logs
    timestamp_patterns = [
        r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)',  # 2023-01-01 12:34:56.789
        r'^(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)',   # 01/01/2023 12:34:56.789
        r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',              # Jan 1 12:34:56 or Dec 10 06:55:46
        r'^(\d{1,2}\s+\w{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2})',      # 1 Jan 2023 12:34:56
        r'^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?)\]', # [2023-01-01T12:34:56.789] or [2023-01-01T12:34:56.789+00:00] (Jenkins format)
        r'^\[(\d{2}:\d{2}:\d{2})\]',                            # [12:34:56] (Jenkins console)
        r'<span class="timestamp"><b>(\d{2}:\d{2}:\d{2})</b>',   # <span class="timestamp"><b>00:00:00</b> (Jenkins HTML format)
        r'^\[?(\d{2}:\d{2}:\d{2}\.\d+)\]?'                      # 12:34:56.789 or [12:34:56.789] (Jenkins format with milliseconds)
    ]
    
    # Error level patterns
    error_level_pattern = r'\b(ERROR|CRITICAL|FATAL|EXCEPTION|WARNING|WARN|INFO|DEBUG)\b'
    
    for i, line in enumerate(lines):
        # Skip empty lines
        if not line.strip():
            continue
        
        # Clean the line by removing ANSI color codes
        clean_line = re.sub(r'\[\d+(?:;\d+)*m', '', line)
        
        # Extract timestamp if present
        timestamp = None
        for pattern in timestamp_patterns:
            match = re.search(pattern, clean_line)
            if match:
                timestamp = match.group(1)
                break
                
        # Special handling for Jenkins ANSI logs with timestamps in brackets
        if not timestamp:
            jenkins_ansi_match = re.search(r'^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\]', clean_line)
            if jenkins_ansi_match:
                timestamp = jenkins_ansi_match.group(1)
        
        # Extract error level
        error_level = None
        error_match = re.search(error_level_pattern, clean_line, re.IGNORECASE)
        if error_match:
            error_level = error_match.group(1).upper()
        
        # Get context lines for better analysis
        context_start = max(0, i - 2)
        context_end = min(len(lines), i + 3)
        context = lines[context_start:context_end]
        
        # If we don't have an error level but the line has common error indicators
        if not error_level and any(err in clean_line.lower() for err in ['error', 'exception', 'fail', 'crash', 'problem', 'build failure']):
            error_level = 'ERROR'
        
        # Default to INFO if no error level found
        error_level = error_level or 'INFO'
        
        # Extract the actual error message
        actual_message = clean_line
        # Use the enhanced component extraction to avoid false positives
        component = enhanced_extract_component(clean_line, error_level)
        if component != 'Unknown' and component is not None:
            # Try to extract just the error message by removing component prefix
            if component == 'sshd' and re.search(r'\w+\[(\d+)\]:', clean_line):
                # For OpenSSH logs, extract the message after the colon
                msg_match = re.search(r'\w+\[(\d+)\]:(.*)', clean_line)
                if msg_match:
                    actual_message = msg_match.group(2).strip()
            elif re.search(r'^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\]', clean_line):
                # For Jenkins logs with timestamps in brackets
                if re.search(r'^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\]\s+\[\w+\]\s+\[[\w\.-]+\]\s+(.*)', clean_line):
                    # Standard Jenkins log format: [timestamp] [level] [component] message
                    msg_match = re.search(r'^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\]\s+\[\w+\]\s+\[[\w\.-]+\]\s+(.*)', clean_line)
                    actual_message = msg_match.group(1)
                elif re.search(r'^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\]\s+' + component + r':', clean_line):
                    # Jenkins ANSI log format: [timestamp] component: message
                    msg_match = re.search(r'^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\]\s+' + component + r':(.*)', clean_line)
                    if msg_match:
                        actual_message = component + ": " + msg_match.group(1).strip()
            else:
                # For other log formats
                msg_match = re.search(r'\[[^\]]+\]\s*(.+)|\b[\w\.-]+:\s*(.+)', clean_line)
                if msg_match:
                    if msg_match.group(1):
                        actual_message = msg_match.group(1)
                    elif msg_match.group(2):
                        actual_message = msg_match.group(2)
        
        # If we still have a timestamp in the component, fix it
        if not timestamp and component and ':' in component and component[0].isdigit():
            # This might be a timestamp
            if re.match(r'\d{2}:\d{2}:\d{2}', component):
                timestamp = component
                component = 'Unknown'
        
        entries.append({
            'timestamp': timestamp,
            'level': error_level,
            'message': actual_message,
            'raw_message': line,
            'severity': ERROR_LEVELS.get(error_level, 1),
            'context': context,
            'component': component,
            'line_number': i + 1
        })
    
    # Sort by timestamp if available, then by severity, then by line number
    def sort_key(entry):
        try:
            # Parse timestamp for proper sorting
            if entry['timestamp']:
                dt = datetime.strptime(entry['timestamp'], '%Y-%m-%d %H:%M:%S')
                return (0, dt, -entry['severity'], entry['line_number'])
        except (ValueError, TypeError):
            pass
        
        # Fallback if timestamp can't be parsed
        has_timestamp = 0 if entry['timestamp'] else 1
        # Sort by severity (higher is more severe)
        severity = -entry['severity']
        return (has_timestamp, datetime.min, severity, entry['line_number'])
    
    try:
        sorted_entries = sorted(entries, key=sort_key)
    except Exception as e:
        # Fallback sorting if there are issues with timestamp parsing
        sorted_entries = sorted(entries, key=lambda x: (0 if x['timestamp'] else 1, -x['severity'], x['line_number']))
    
    return sorted_entries

def extract_component(line, level=None):
    """Extract the component name from a log line"""
    # First, strip ANSI color codes that might be present in Jenkins console logs
    # Pattern for ANSI color codes like [2;31m[2;1m
    clean_line = re.sub(r'\[\d+(?:;\d+)*m', '', line)
    
    # Filter out timestamp patterns that might look like components
    # Filter out timestamps in brackets like [2025-02-27T05:52:32/367Z]
    filtered_message = re.sub(r'\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\]]*\]', '', clean_line)
    filtered_message = re.sub(r'\[\d{2}:\d{2}:\d{2}(?:\.\d+)?\]', '', filtered_message)  # Also remove [HH:MM:SS] timestamps
    
    # Handle Jenkins log format: [2023-05-15T10:30:45.123Z] [INFO] [jenkins.main] Starting Jenkins
    jenkins_log_match = re.search(r'\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\]\s+\[\w+\]\s+\[([\w\.-]+)\]', clean_line)
    if jenkins_log_match:
        return jenkins_log_match.group(1)  # e.g., jenkins.main
    
    # Handle Jenkins console logs with ANSI color codes: [2025-03-03T03:03:41.029Z] [2;31m[2;1mgitw: Error: please make sure this are supported
    jenkins_console_match = re.search(r'^\s*\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\]\s+([\w\.-]+):', clean_line)
    if jenkins_console_match:
        return jenkins_console_match.group(1)  # e.g., gitw
    
    # Handle OpenSSH log format: Dec 10 06:55:46 LabSZ sshd[24200]: message
    ssh_log_match = re.search(r'(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+)\[(\d+)\]:', clean_line)
    if ssh_log_match:
        # Extract the component name without the PID
        return ssh_log_match.group(3)  # e.g., sshd
    
    # Check for Windows paths and exclude them from component extraction
    # This needs to be done before the general component patterns
    windows_path_patterns = [
        r'\b([A-Z]):\\',  # C:\, D:\, etc.
        r'\b([A-Z]):(?![\\])',  # C:, D:, etc. (not followed by backslash)
    ]
    
    for pattern in windows_path_patterns:
        if re.search(pattern, filtered_message, re.IGNORECASE):
            # If we find a Windows path, we need to be more careful with component extraction
            # We'll only extract components that are in specific formats
            
            # Try to extract components in brackets
            bracket_component = re.search(r'\[([\w\.-]+)\]', filtered_message)
            if bracket_component:
                component = bracket_component.group(1)
                # Skip if the component is a common error level
                if component.upper() in ['ERROR', 'INFO', 'WARNING', 'DEBUG', 'WARN', 'FATAL', 'CRITICAL']:
                    continue
                return component
            
            # If no bracketed component, look for components with dots (likely module paths)
            module_component = re.search(r'\b([\w]+\.[\w\.]+):', filtered_message)
            if module_component:
                return module_component.group(1)
                
            # If we can't find a clear component, return Unknown
            return "Unknown"
    
    # Try to extract components from common log prefixes first
    prefixes = ['module', 'component', 'service', 'class', 'function', 'method']
    for prefix in prefixes:
        match = re.search(rf'\b{prefix}\s+["\']?([\w\.-]+)["\']?', filtered_message, re.IGNORECASE)
        if match:
            component = match.group(1)
            # Skip if it's just a single letter or number
            if len(component) <= 1 or component.isdigit():
                continue
            return component
    
    # Handle other common log formats
    component_patterns = [
        r'\[([a-zA-Z0-9\.-]+)\]',  # [component]
        r'([a-zA-Z0-9\.-]+):',     # component:
    ]
    
    for pattern in component_patterns:
        match = re.search(pattern, filtered_message)
        if match:
            component = match.group(1)
            # Skip if the component looks like a timestamp
            if re.match(r'\d{2}:\d{2}:\d{2}', component):
                continue
            # Skip if the component is a common error level
            if component.upper() in ['ERROR', 'INFO', 'WARNING', 'DEBUG', 'WARN', 'FATAL', 'CRITICAL']:
                continue
            # Skip if the component is a common log prefix
            if component.upper() in ['LOG', 'LOGGER', 'LOGGING', 'SYSTEM', 'APP', 'APPLICATION']:
                continue
            # Skip if the component looks like a Windows drive letter (e.g., C:, D:)
            if re.match(r'^[A-Z]:$', component, re.IGNORECASE):
                continue
            # Skip if the component looks like the start of a Windows file path (e.g., C:\, D:\)
            if re.match(r'^[A-Z]:\\', component, re.IGNORECASE):
                continue
            
            # Skip single letters and other low-quality components
            if len(component) <= 1:
                continue
                
            # Skip common units like 'ms', 's', 'KB', 'MB', etc.
            if component.lower() in ['ms', 's', 'kb', 'mb', 'gb', 'tb', 'b']:
                continue
                
            # Skip numeric-only components
            if re.match(r'^\d+$', component):
                continue
                
            # Skip components that are likely not actual components
            # This includes common words that appear in logs but aren't components
            common_words = [
                'error', 'warning', 'info', 'debug', 'the', 'a', 'an', 'in', 'on', 'at', 'to', 'from', 
                'with', 'by', 'for', 'and', 'or', 'not', 'is', 'was', 'be', 'been', 'being', 'am', 'are', 
                'component', 'module', 'function', 'method', 'class', 'service', 'system'
            ]
            if component.lower() in common_words:
                continue
                
            # Remove trailing colon if present
            component = component.rstrip(':')
            
            # Skip components that are too short and don't contain dots (likely not meaningful)
            if len(component) < 3 and '.' not in component:
                continue
                
            return component
    
    # Look for components after "Component" or similar words in the text
    component_prefix_match = re.search(r'(?:component|module|service)\s+([A-Za-z][A-Za-z0-9\._-]+)', filtered_message, re.IGNORECASE)
    if component_prefix_match:
        component = component_prefix_match.group(1)
        # Skip if it's just a single letter or number
        if len(component) <= 1 or component.isdigit():
            return "Unknown"
        return component
    
    # If no component found
    return "Unknown"

def analyze_log_entries(entries):
    """Analyze log entries to find patterns and root causes"""
    # Load known patterns for matching
    try:
        patterns_db = load_patterns()
        jenkins_patterns = patterns_db['jenkins_patterns']
        system_patterns = patterns_db['system_patterns']
        all_patterns = jenkins_patterns + system_patterns
    except Exception as e:
        logger.warning(f"Failed to load patterns: {str(e)}")
        jenkins_patterns = []
        system_patterns = []
        all_patterns = []
    
    # Group errors by component
    components = {}
    unknown_count = 0
    
    for entry in entries:
        component = entry['component']
        # Count unknown components separately
        if component == "Unknown":
            unknown_count += 1
            continue
            
        if component not in components:
            components[component] = 0
        components[component] += 1
    
    # Find the most problematic components - don't limit
    # Only include components with at least 2 occurrences to filter out noise
    problematic_components = [(comp, count) for comp, count in sorted(components.items(), key=lambda x: x[1], reverse=True) if count >= 2]
    
    # If we have too few components after filtering, include some with single occurrences
    if len(problematic_components) < 5:
        additional_components = [(comp, count) for comp, count in sorted(components.items(), key=lambda x: x[1], reverse=True) if count == 1]
        problematic_components.extend(additional_components[:5 - len(problematic_components)])
    
    # Add Unknown as a component if there are any unknown entries
    if unknown_count > 0:
        problematic_components.append(("Unknown", unknown_count))
    
    # Identify critical issues and categorize by level
    critical_issues = [e for e in entries if e['severity'] >= 3]
    error_by_level = {
        'ERROR': len([e for e in entries if e['level'] == 'ERROR']),
        'CRITICAL': len([e for e in entries if e['level'] == 'CRITICAL' or e['level'] == 'FATAL']),
        'WARNING': len([e for e in entries if e['level'] == 'WARNING' or e['level'] == 'WARN']),
        'EXCEPTION': len([e for e in entries if e['level'] == 'EXCEPTION'])
    }
    
    # Match against known patterns
    pattern_matches = []
    jenkins_specific_issues = []
    
    for entry in entries:
        message = entry.get('message', '')
        raw_message = entry.get('raw_message', message)
        
        for pattern in all_patterns:
            pattern_regex = pattern['pattern']
            try:
                if re.search(pattern_regex, raw_message, re.IGNORECASE):
                    pattern_match = {
                        'pattern_id': pattern['id'],
                        'pattern_name': pattern['name'],
                        'severity': pattern['severity'],
                        'description': pattern['description'],
                        'suggestion': pattern['suggestion'],
                        'matched_line': raw_message,
                        'timestamp': entry.get('timestamp', ''),
                        'component': entry.get('component', 'Unknown')
                    }
                    pattern_matches.append(pattern_match)
                    
                    # For KPI tracking
                    try:
                        update_error_kpi(pattern['name'])
                    except:
                        pass
                    
                    # Special handling for Jenkins-specific issues
                    if pattern in jenkins_patterns:
                        jenkins_specific_issues.append(pattern_match)
            except Exception as e:
                continue
    
    # Track time distribution of errors to identify spikes
    time_distribution = {}
    try:
        for entry in entries:
            if entry['timestamp'] and entry['level'] in ['ERROR', 'CRITICAL', 'FATAL', 'EXCEPTION', 'WARNING', 'WARN']:
                # Handle different timestamp formats
                timestamp = entry['timestamp']
                hour = None
                
                # Try different timestamp formats
                if ' ' in timestamp:
                    # Format: 2023-01-01 12:34:56 or similar
                    hour = timestamp.split(' ')[1].split(':')[0]
                elif 'T' in timestamp:
                    # Format: 2023-01-01T12:34:56 (ISO format)
                    hour = timestamp.split('T')[1].split(':')[0]
                elif ':' in timestamp:
                    # Format: 12:34:56 (time only)
                    hour = timestamp.split(':')[0]
                
                # If we still couldn't parse the hour, try a more generic approach
                if not hour and re.search(r'\d{2}:\d{2}', timestamp):
                    # Extract the first occurrence of HH:MM
                    match = re.search(r'(\d{2}):\d{2}', timestamp)
                    if match:
                        hour = match.group(1)
                
                if hour:
                    if hour not in time_distribution:
                        time_distribution[hour] = 0
                    time_distribution[hour] += 1
    except Exception as e:
        logger.error(f"Error parsing timestamps for timeline: {str(e)}")
        # Fallback if timestamps can't be parsed
        time_distribution = {}
    
    # Find common error patterns by analyzing the actual message content
    error_patterns = {}
    for entry in entries:
        if entry['level'] in ['ERROR', 'CRITICAL', 'FATAL', 'EXCEPTION']:
            # Better extraction of the error type - look for common patterns
            message = entry['message']
            
            # Extract common exception names
            exception_match = re.search(r'(?:Exception|Error|Failure):\s*([^:]+)', message)
            if exception_match:
                error_type = exception_match.group(1).strip()
            elif ':' in message:
                # Use the part before the first colon as the error type
                error_type = message.split(':', 1)[0].strip()
            else:
                # Take the first 30 chars to avoid overly long keys
                error_type = message[:30].strip()
            
            # Add error type to patterns
            if error_type not in error_patterns:
                error_patterns[error_type] = {
                    'count': 0,
                    'examples': [],
                    'components': set(),
                    'timestamps': []
                }
            error_patterns[error_type]['count'] += 1
            if len(error_patterns[error_type]['examples']) < 3:
                error_patterns[error_type]['examples'].append(message)
            error_patterns[error_type]['components'].add(entry['component'])
            if entry['timestamp']:
                error_patterns[error_type]['timestamps'].append(entry['timestamp'])
    
    # Convert to sorted list of tuples with more info - don't limit
    most_common_errors = []
    for error_type, data in sorted(error_patterns.items(), key=lambda x: x[1]['count'], reverse=True):
        try:
            components_list = list(data['components'])
            most_common_errors.append({
                'error_type': error_type,
                'count': data['count'],
                'example': data['examples'][0] if data['examples'] else '',
                'affects_components': components_list,  # Don't limit component list
                'first_seen': min(data['timestamps']) if data['timestamps'] else None,
                'last_seen': max(data['timestamps']) if data['timestamps'] else None,
            })
        except Exception as e:
            # Fallback for any data structure errors
            most_common_errors.append({
                'error_type': str(error_type),
                'count': data['count'] if isinstance(data, dict) and 'count' in data else 1,
                'example': str(data)[:100] if not isinstance(data, dict) else '',
            })
    
    # Find error chains - more sophisticated correlation
    error_chains = []
    if len(entries) > 1:
        # Group by component to find related errors in the same component
        errors_by_component = {}
        for entry in entries:
            if entry['level'] in ['ERROR', 'CRITICAL', 'FATAL', 'EXCEPTION']:
                comp = entry['component']
                if comp not in errors_by_component:
                    errors_by_component[comp] = []
                errors_by_component[comp].append(entry)
        
        # For each component with multiple errors, look for chains
        for comp, comp_errors in errors_by_component.items():
            if len(comp_errors) > 1:
                for i in range(len(comp_errors) - 1):
                    if comp_errors[i]['timestamp'] and comp_errors[i+1]['timestamp']:
                        # Check if they're within a reasonable time window (5 minutes)
                        try:
                            t1 = datetime.strptime(comp_errors[i]['timestamp'], '%Y-%m-%d %H:%M:%S')
                            t2 = datetime.strptime(comp_errors[i+1]['timestamp'], '%Y-%m-%d %H:%M:%S')
                            time_diff = (t2 - t1).total_seconds()
                            
                            # If errors happened close to each other, they might be related
                            if 0 <= time_diff <= 300:  # within 5 minutes
                                error_chains.append({
                                    'from': comp_errors[i],
                                    'to': comp_errors[i+1],
                                    'time_diff': f"{time_diff:.1f} seconds"
                                })
                        except:
                            # Fallback for timestamp parsing issues
                            error_chains.append({
                                'from': comp_errors[i],
                                'to': comp_errors[i+1],
                            })
    
    # No longer limiting chains to 10
    
    return {
        'problematic_components': problematic_components,  # No longer limiting to 5
        'critical_issues_count': len(critical_issues),
        'error_by_level': error_by_level,
        'time_distribution': dict(sorted(time_distribution.items())),
        'error_chains': error_chains,
        'most_common_errors': most_common_errors,
        'pattern_matches': pattern_matches,
        'jenkins_specific_issues': jenkins_specific_issues,
        'total_issues': len(entries)
    }

def generate_recommendations(entries, analysis):
    """Generate recommendations based on log analysis"""
    recommendations = []
    
    # Ensure error_by_level exists in the analysis
    if 'error_by_level' not in analysis:
        analysis['error_by_level'] = {
            'ERROR': len([e for e in entries if e['level'] == 'ERROR']),
            'CRITICAL': len([e for e in entries if e['level'] == 'CRITICAL' or e['level'] == 'FATAL']),
            'WARNING': len([e for e in entries if e['level'] == 'WARNING' or e['level'] == 'WARN']),
            'EXCEPTION': len([e for e in entries if e['level'] == 'EXCEPTION'])
        }
    
    # General recommendations based on common patterns
    if analysis['critical_issues_count'] > 0:
        recommendations.append({
            'title': 'Address Critical Issues',
            'description': f'There are {analysis["critical_issues_count"]} critical issues that need immediate attention.',
            'steps': ['Review critical errors in order of occurrence', 
                     'Check system resource usage during error periods', 
                     'Verify service dependencies are functioning correctly']
        })
    
    # Component-specific recommendations
    if analysis['problematic_components']:
        component, _ = analysis['problematic_components'][0]
        recommendations.append({
            'title': f'Investigate {component}',
            'description': f'The {component} component shows the highest error rate and might be the source of problems.',
            'steps': [f'Check {component} configuration and logs in detail', 
                     'Verify if recent changes were made to this component', 
                     'Consider restarting or rolling back recent changes to this component']
        })
    
    # Error pattern recommendations
    if analysis['most_common_errors']:
        error = analysis['most_common_errors'][0]
        if isinstance(error, dict) and 'error_type' in error:
            error_type = error['error_type']
        elif isinstance(error, tuple) and len(error) >= 1:
            error_type = error[0]
        else:
            error_type = str(error)
            
        recommendations.append({
            'title': 'Common Error Pattern',
            'description': f'The error pattern "{error_type}" appears frequently and should be addressed.',
            'steps': ['Search knowledge base or documentation for this error pattern',
                     'Check for known bugs or issues related to this error',
                     'Consider if a configuration change could address this pattern']
        })
    
    # Add general troubleshooting steps
    recommendations.append({
        'title': 'General Troubleshooting',
        'description': 'Basic steps that can help identify and resolve issues.',
        'steps': ['Check system resources (CPU, memory, disk space, network)',
                 'Verify all services are running with correct permissions',
                 'Look for recent deployments or configuration changes',
                 'Check for external dependencies that might be failing']
    })
    
    return recommendations

@app.route('/patterns')
@login_required
def show_patterns():
    """Show and manage error patterns"""
    try:
        with open(app.config['PATTERNS_FILE'], 'r') as f:
            patterns = json.load(f)
    except Exception as e:
        patterns = {
            'jenkins_patterns': [],
            'system_patterns': []
        }
        flash(f"Error loading patterns: {str(e)}")
    
    return render_template('patterns.html', patterns=patterns, user=session)

@app.route('/kpi')
@login_required
def show_kpi():
    """Show KPI statistics about errors"""
    try:
        with open(app.config['KPI_FILE'], 'r') as f:
            kpi_data = json.load(f)
            
        # Ensure data structure is valid and populate with defaults if missing
        if 'error_occurrences' not in kpi_data:
            kpi_data['error_occurrences'] = {}
        if 'common_patterns' not in kpi_data:
            kpi_data['common_patterns'] = {}
        if 'related_errors' not in kpi_data:
            kpi_data['related_errors'] = {}
        if 'total_logs_analyzed' not in kpi_data:
            kpi_data['total_logs_analyzed'] = 0
        if 'errors_by_date' not in kpi_data:
            kpi_data['errors_by_date'] = {}
            
        # If no data yet, populate with dummy data for demo
        if not kpi_data['error_occurrences'] and not kpi_data['errors_by_date']:
            # Create some sample data for demo
            today = datetime.now().strftime('%Y-%m-%d')
            yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            two_days_ago = (datetime.now() - timedelta(days=2)).strftime('%Y-%m-%d')
            
            # Sample errors
            kpi_data['error_occurrences'] = {
                "Build Failure": 5,
                "Maven Compilation Error": 4,
                "Connection Timeout": 3,
                "NPM Package Error": 2,
                "Out of Memory": 1
            }
            
            # Sample dates
            kpi_data['errors_by_date'] = {
                two_days_ago: {
                    "Build Failure": 2,
                    "Maven Compilation Error": 1,
                    "Connection Timeout": 1,
                },
                yesterday: {
                    "Build Failure": 2, 
                    "Maven Compilation Error": 2,
                    "NPM Package Error": 1,
                    "Out of Memory": 1,
                },
                today: {
                    "Build Failure": 1,
                    "Maven Compilation Error": 1,
                    "Connection Timeout": 2,
                    "NPM Package Error": 1
                }
            }
            
            kpi_data['total_logs_analyzed'] = 8
            
            # Save this sample data
            with open(app.config['KPI_FILE'], 'w') as f:
                json.dump(kpi_data, f, indent=2)
                
    except Exception as e:
        logger.error(f"Error loading KPI data: {str(e)}")
        kpi_data = {
            'error_occurrences': {
                "Build Failure": 5,
                "Maven Compilation Error": 4,
                "Connection Timeout": 3,
                "NPM Package Error": 2,
                "Out of Memory": 1
            },
            'common_patterns': {},
            'related_errors': {},
            'total_logs_analyzed': 8,
            'errors_by_date': {
                (datetime.now() - timedelta(days=2)).strftime('%Y-%m-%d'): {
                    "Build Failure": 2,
                    "Maven Compilation Error": 1,
                    "Connection Timeout": 1,
                },
                (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d'): {
                    "Build Failure": 2, 
                    "Maven Compilation Error": 2,
                    "NPM Package Error": 1,
                    "Out of Memory": 1,
                },
                datetime.now().strftime('%Y-%m-%d'): {
                    "Build Failure": 1,
                    "Maven Compilation Error": 1,
                    "Connection Timeout": 2,
                    "NPM Package Error": 1
                }
            }
        }
        flash(f"Error loading KPI data, using demo data: {str(e)}")
    
    # Process data for charts
    dates = sorted(kpi_data.get('errors_by_date', {}).keys())
    error_types = set()
    for date_data in kpi_data.get('errors_by_date', {}).values():
        for error_type in date_data.keys():
            error_types.add(error_type)
    
    error_trends = {}
    for error_type in error_types:
        error_trends[error_type] = [
            kpi_data.get('errors_by_date', {}).get(date, {}).get(error_type, 0)
            for date in dates
        ]
    
    # Sort error occurrences
    top_errors = sorted(
        kpi_data.get('error_occurrences', {}).items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]  # Top 10 errors
    
    # Create a proper user object from session data
    user = None
    if 'user_id' in session:
        user = {
            'id': session.get('user_id'),
            'username': session.get('username'),
            'role': session.get('role')
        }
    
    return render_template('kpi.html', 
                           kpi_data=kpi_data, 
                           dates=dates, 
                           error_trends=error_trends,
                           top_errors=top_errors,
                           user=user)

@app.route('/add_pattern', methods=['POST'])
@login_required
def add_pattern():
    """Add a new error pattern"""
    # Verify user is admin
    if session.get('role') != ROLE_ADMIN:
        flash("Only administrators can add patterns")
        return redirect(url_for('show_patterns'))
    
    try:
        pattern_name = request.form['pattern_name']
        pattern_regex = request.form['pattern_regex']
        pattern_type = request.form['pattern_type']
        severity = request.form['severity']
        description = request.form['description']
        suggestion = request.form['suggestion']
        
        # Additional parameters for improved pattern matching
        exclude_paths = 'exclude_paths' in request.form
        exclude_timestamp = 'exclude_timestamp' in request.form
        
        # Load current patterns
        with open(app.config['PATTERNS_FILE'], 'r') as f:
            patterns = json.load(f)
        
        # Generate a new ID
        all_ids = []
        for category in patterns.values():
            all_ids.extend([p['id'] for p in category])
        new_id = max(all_ids) + 1 if all_ids else 1
        
        # Create new pattern
        new_pattern = {
            'id': new_id,
            'name': pattern_name,
            'pattern': pattern_regex,
            'severity': severity,
            'description': description,
            'suggestion': suggestion,
            'exclude_paths': exclude_paths,
            'exclude_timestamp': exclude_timestamp,
            'effectiveness_score': 1.0,  # Initialize with perfect score
            'false_positive_count': 0,
            'match_count': 0,
            'created_by': session.get('username', 'Unknown'),
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Add to appropriate category
        if pattern_type == 'jenkins':
            patterns['jenkins_patterns'].append(new_pattern)
        else:
            patterns['system_patterns'].append(new_pattern)
        
        # Save updated patterns
        with open(app.config['PATTERNS_FILE'], 'w') as f:
            json.dump(patterns, f, indent=2)
        
        # If the pattern was created from a log analysis, redirect back to the analysis
        log_id = request.form.get('log_id', '')
        if log_id:
            flash(f"Pattern '{pattern_name}' added successfully")
            return redirect(url_for('view_analysis', analysis_id=log_id))
            
        flash(f"Pattern '{pattern_name}' added successfully")
    except Exception as e:
        flash(f"Error adding pattern: {str(e)}")
    
    return redirect(url_for('show_patterns'))

@app.route('/edit_pattern/<int:pattern_id>', methods=['POST'])
@login_required
def edit_pattern(pattern_id):
    """Edit an existing pattern"""
    # Verify user is admin
    if session.get('role') != ROLE_ADMIN:
        flash("Only administrators can edit patterns")
        return redirect(url_for('show_patterns'))
    
    try:
        pattern_name = request.form['pattern_name']
        pattern_regex = request.form['pattern_regex']
        severity = request.form['severity']
        description = request.form['description']
        suggestion = request.form['suggestion']
        exclude_paths = 'exclude_paths' in request.form
        exclude_timestamp = 'exclude_timestamp' in request.form
        
        # Load current patterns
        with open(app.config['PATTERNS_FILE'], 'r') as f:
            patterns = json.load(f)
        
        # Find and update the pattern
        pattern_found = False
        for category in patterns.values():
            for pattern in category:
                if pattern['id'] == pattern_id:
                    pattern['name'] = pattern_name
                    pattern['pattern'] = pattern_regex
                    pattern['severity'] = severity
                    pattern['description'] = description
                    pattern['suggestion'] = suggestion
                    pattern['exclude_paths'] = exclude_paths
                    pattern['exclude_timestamp'] = exclude_timestamp
                    pattern['updated_by'] = session.get('username', 'Unknown')
                    pattern['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    pattern_found = True
                    break
            if pattern_found:
                break
        
        if not pattern_found:
            flash(f"Pattern with ID {pattern_id} not found")
            return redirect(url_for('show_patterns'))
        
        # Save updated patterns
        with open(app.config['PATTERNS_FILE'], 'w') as f:
            json.dump(patterns, f, indent=2)
        
        # If the edit came from a log analysis, redirect back to the analysis
        log_id = request.form.get('log_id', '')
        if log_id:
            flash(f"Pattern '{pattern_name}' updated successfully")
            return redirect(url_for('view_analysis', analysis_id=log_id))
        
        flash(f"Pattern '{pattern_name}' updated successfully")
    except Exception as e:
        flash(f"Error updating pattern: {str(e)}")
    
    return redirect(url_for('show_patterns'))

@app.route('/delete_pattern/<int:pattern_id>', methods=['POST'])
@login_required
def delete_pattern(pattern_id):
    """Delete an error pattern"""
    # Verify user is admin
    if session.get('role') != ROLE_ADMIN:
        flash("Only administrators can delete patterns")
        return redirect(url_for('show_patterns'))
    
    try:
        # Load current patterns
        with open(app.config['PATTERNS_FILE'], 'r') as f:
            patterns = json.load(f)
        
        # Find and remove the pattern
        pattern_name = None
        for category_name, category_patterns in patterns.items():
            for i, pattern in enumerate(category_patterns):
                if pattern['id'] == pattern_id:
                    pattern_name = pattern['name']
                    patterns[category_name].pop(i)
                    break
            if pattern_name:
                break
        
        if not pattern_name:
            flash(f"Pattern with ID {pattern_id} not found")
            return redirect(url_for('show_patterns'))
        
        # Save updated patterns
        with open(app.config['PATTERNS_FILE'], 'w') as f:
            json.dump(patterns, f, indent=2)
        
        flash(f"Pattern '{pattern_name}' deleted successfully")
    except Exception as e:
        flash(f"Error deleting pattern: {str(e)}")
    
    return redirect(url_for('show_patterns'))

# User authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please provide both username and password')
            return render_template('login.html')
        
        try:
            with open(app.config['USERS_FILE'], 'r') as f:
                users_data = json.load(f)
            
            # Find user by username
            user = next((u for u in users_data['users'] if u['username'] == username), None)
            
            if user:
                # Check password
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                if password_hash == user['password_hash']:
                    # Set session
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    
                    # Redirect to next parameter or default to index
                    next_page = request.args.get('next', url_for('index'))
                    return redirect(next_page)
            
            flash('Invalid username or password')
        except Exception as e:
            flash(f'Login error: {str(e)}')
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, password, confirm_password]):
            flash('All fields are required')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('register.html')
        
        try:
            with open(app.config['USERS_FILE'], 'r') as f:
                users_data = json.load(f)
            
            # Check if username already exists
            if any(u['username'] == username for u in users_data['users']):
                flash('Username already exists')
                return render_template('register.html')
            
            # Create new user
            new_user = {
                'id': str(uuid.uuid4()),
                'username': username,
                'password_hash': hashlib.sha256(password.encode()).hexdigest(),
                'role': ROLE_USER,  # Default role is user
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'logs': []
            }
            
            users_data['users'].append(new_user)
            
            with open(app.config['USERS_FILE'], 'w') as f:
                json.dump(users_data, f, indent=2)
            
            flash('Registration successful! You can now log in')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Registration error: {str(e)}')
    
    return render_template('register.html')

@app.route('/admin/users')
@admin_required
def admin_users():
    try:
        # Completely rebuild the session data for the template
        current_user = {
            'id': session.get('user_id', ''),
            'username': session.get('username', 'Admin'),
            'role': session.get('role', 'admin')
        }
        
        # Read and prepare user data
        with open(app.config['USERS_FILE'], 'r') as f:
            users_data = json.load(f)
        
        # Prepare users for template
        users_list = []
        for user_data in users_data.get('users', []):
            # Create processed user objects with safe values for template
            processed_user = {
                'id': user_data.get('id', ''),
                'username': user_data.get('username', ''),
                'role': user_data.get('role', 'user'),
                'created_at': user_data.get('created_at', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                'logs': []
            }
            
            # Process logs safely
            if 'logs' in user_data and isinstance(user_data['logs'], list):
                processed_user['logs'] = user_data['logs']
            
            users_list.append(processed_user)
                
        return render_template('admin_users.html', users=users_list, user=current_user)
    except Exception as e:
        logger.error(f'Error in admin_users: {str(e)}')
        flash(f'Error loading users: {str(e)}')
        return redirect(url_for('index'))

@app.route('/admin/user/<user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    try:
        with open(app.config['USERS_FILE'], 'r') as f:
            users_data = json.load(f)
        
        # Remove user with the given ID
        users_data['users'] = [u for u in users_data['users'] if u['id'] != user_id]
        
        with open(app.config['USERS_FILE'], 'w') as f:
            json.dump(users_data, f, indent=2)
        
        flash('User deleted successfully')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<user_id>/toggle_role', methods=['POST'])
@admin_required
def toggle_user_role(user_id):
    try:
        with open(app.config['USERS_FILE'], 'r') as f:
            users_data = json.load(f)
        
        # Find user and toggle role
        for user in users_data['users']:
            if user['id'] == user_id:
                user['role'] = ROLE_ADMIN if user['role'] == ROLE_USER else ROLE_USER
                break
        
        with open(app.config['USERS_FILE'], 'w') as f:
            json.dump(users_data, f, indent=2)
        
        flash('User role updated successfully')
    except Exception as e:
        flash(f'Error updating user role: {str(e)}')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/grant_admin', methods=['POST'])
@admin_required
def grant_admin():
    try:
        user_id = request.form.get('user_id')
        
        if not user_id:
            flash('No user selected')
            return redirect(url_for('admin_users'))
            
        with open(app.config['USERS_FILE'], 'r') as f:
            users_data = json.load(f)
        
        # Find user and set role to admin
        user_found = False
        for user in users_data['users']:
            if user['id'] == user_id:
                user['role'] = ROLE_ADMIN
                user_found = True
                username = user['username']
                break
        
        if not user_found:
            flash('User not found')
            return redirect(url_for('admin_users'))
            
        with open(app.config['USERS_FILE'], 'w') as f:
            json.dump(users_data, f, indent=2)
        
        flash(f'Admin privileges granted to {username}')
    except Exception as e:
        flash(f'Error granting admin privileges: {str(e)}')
    
    return redirect(url_for('admin_users'))

# Main route
@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('index.html', user=session)
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'logfile' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['logfile']
    
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        # Add user ID prefix to ensure uniqueness
        user_id = session['user_id']
        user_filename = f"{user_id}_{secure_filename(file.filename)}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], user_filename)
        file.save(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
            
            log_entries = parse_log(log_content)
            
            # Handle error if no entries found
            if not log_entries:
                flash('No valid log entries found in the file. Please check the format.')
                return redirect(url_for('index'))
                
            try:
                analysis = analyze_log_entries(log_entries)
                recommendations = generate_recommendations(log_entries, analysis)
                
                # Save the analysis results
                result_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{user_filename}_analysis.json")
                with open(result_path, 'w') as f:
                    # Use a default JSON encoder to handle sets
                    class SetEncoder(json.JSONEncoder):
                        def default(self, obj):
                            if isinstance(obj, set):
                                return list(obj)
                            return json.JSONEncoder.default(self, obj)
                    
                    # Create analysis result
                    analysis_result = {
                        'entries': log_entries,
                        'analysis': analysis,
                        'recommendations': recommendations,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'filename': user_filename,
                        'original_filename': file.filename,
                        'user_id': user_id,
                        'username': session.get('username', 'Unknown')
                    }
                    
                    json.dump(analysis_result, f, indent=2, cls=SetEncoder)
                    
                    # Add to user's logs
                    try:
                        with open(app.config['USERS_FILE'], 'r') as users_f:
                            users_data = json.load(users_f)
                            
                        for user in users_data['users']:
                            if user['id'] == user_id:
                                user['logs'].append({
                                    'filename': user_filename,
                                    'original_filename': file.filename,
                                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'critical_issues': analysis['critical_issues_count']
                                })
                                break
                                
                        with open(app.config['USERS_FILE'], 'w') as users_f:
                            json.dump(users_data, users_f, indent=2)
                    except Exception as e:
                        logger.warning(f"Error updating user logs: {str(e)}")
                
                return redirect(url_for('show_analysis', filename=user_filename))
            except Exception as analysis_error:
                logger.exception(f"Error analyzing log file: {str(analysis_error)}")
                flash(f'Error analyzing log content: {str(analysis_error)}')
                
                # Even if analysis fails, we can still show the raw entries
                result_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{user_filename}_basic_analysis.json")
                with open(result_path, 'w') as f:
                    # Count issues by component even in basic mode
                    component_counts = {}
                    for entry in log_entries:
                        component = entry.get('component', 'Unknown')
                        if component not in component_counts:
                            component_counts[component] = 0
                        component_counts[component] += 1
                    
                    # Find the most problematic components
                    problematic_components = sorted(component_counts.items(), key=lambda x: x[1], reverse=True)
                    
                    # Get error messages for critical issues
                    critical_entries = [e for e in log_entries if e.get('severity', 0) >= 3]
                    critical_messages = []
                    for entry in critical_entries[:5]:  # Take the first 5 critical issues
                        critical_messages.append({
                            'message': entry.get('message', 'Unknown error'),
                            'component': entry.get('component', 'Unknown'),
                            'timestamp': entry.get('timestamp', 'Unknown time')
                        })
                    
                    # Format the error that caused analysis to fail
                    error_reason = str(analysis_error)
                    error_type = analysis_error.__class__.__name__
                    error_location = ""
                    if hasattr(analysis_error, '__traceback__'):
                        import traceback
                        tb = traceback.extract_tb(analysis_error.__traceback__)
                        if tb:
                            error_location = f"in {tb[-1].name} at line {tb[-1].lineno}"
                    
                    # Find similar errors with same component
                    error_patterns = {}
                    for entry in critical_entries:
                        component = entry.get('component', 'Unknown')
                        msg = entry.get('message', '')
                        # Extract key part of message
                        if ':' in msg:
                            key = msg.split(':', 1)[0].strip()
                        else:
                            key = msg[:30].strip()
                        
                        pattern_key = f"{component}:{key}"
                        if pattern_key not in error_patterns:
                            error_patterns[pattern_key] = {'count': 0, 'example': msg}
                        error_patterns[pattern_key]['count'] += 1
                    
                    # Sort by count
                    most_common_errors = []
                    for pattern, data in sorted(error_patterns.items(), key=lambda x: x[1]['count'], reverse=True)[:5]:
                        component = pattern.split(':', 1)[0]
                        error_type = pattern.split(':', 1)[1] if ':' in pattern else pattern
                        most_common_errors.append({
                            'error_type': error_type,
                            'count': data['count'],
                            'example': data['example'],
                            'affects_components': [component]
                        })
                    
                    # Create basic analysis result with user info
                    basic_analysis_result = {
                        'entries': log_entries,
                        'analysis': {
                            'critical_issues_count': len(critical_entries),
                            'problematic_components': problematic_components[:10],  # Limit to 10 components
                            'most_common_errors': most_common_errors,
                            'error_by_level': {
                                'ERROR': len([e for e in log_entries if e['level'] == 'ERROR']),
                                'CRITICAL': len([e for e in log_entries if e['level'] == 'CRITICAL' or e['level'] == 'FATAL']),
                                'WARNING': len([e for e in log_entries if e['level'] == 'WARNING' or e['level'] == 'WARN']),
                                'EXCEPTION': len([e for e in log_entries if e['level'] == 'EXCEPTION']),
                            },
                            'analysis_error': {
                                'message': error_reason,
                                'type': error_type,
                                'location': error_location
                            },
                            'critical_messages': critical_messages,
                            'total_issues': len(log_entries)
                        },
                        'recommendations': [
                            {'title': 'Review Critical Errors First', 
                             'description': f'Focus on the {len(critical_entries)} critical issues identified.',
                             'steps': ['Check each critical error and exception in the timeline', 
                                      'Look for patterns around the timestamps of critical errors',
                                      'Check the most problematic component: ' + (problematic_components[0][0] if problematic_components else 'None')]},
                            {'title': 'Advanced Analysis Failed', 
                             'description': f'Error details: {error_type} - {error_reason}',
                             'steps': ['The log might be too large or complex for detailed analysis',
                                      'Consider analyzing a smaller segment of the log',
                                      'Check for malformed log entries around the time of errors']}
                        ],
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'filename': user_filename,
                        'original_filename': file.filename,
                        'user_id': user_id,
                        'username': session.get('username', 'Unknown'),
                        'is_basic_analysis': True
                    }
                    
                    json.dump(basic_analysis_result, f, indent=2)
                    
                    # Add to user's logs
                    try:
                        with open(app.config['USERS_FILE'], 'r') as users_f:
                            users_data = json.load(users_f)
                            
                        for user in users_data['users']:
                            if user['id'] == user_id:
                                user['logs'].append({
                                    'filename': user_filename,
                                    'original_filename': file.filename,
                                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    'critical_issues': len(critical_entries),
                                    'is_basic_analysis': True
                                })
                                break
                                
                        with open(app.config['USERS_FILE'], 'w') as users_f:
                            json.dump(users_data, users_f, indent=2)
                    except Exception as e:
                        logger.warning(f"Error updating user logs for basic analysis: {str(e)}")
                
                return redirect(url_for('show_analysis', filename=user_filename))
                
        except Exception as e:
            logger.exception(f"Error processing log file: {str(e)}")
            flash(f'Error processing log file: {str(e)}')
            return redirect(url_for('index'))
    else:
        flash('File type not allowed. Please upload .log or .txt files only.')
        return redirect(url_for('index'))

@app.route('/analyze', methods=['POST'])
@login_required
def analyze_text():
    if 'logtext' not in request.form or not request.form['logtext'].strip():
        flash('No log content provided')
        return redirect(url_for('index'))
    
    log_content = request.form['logtext']
    
    try:
        # Save the log content to a file with user prefix
        user_id = session['user_id']
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f"{user_id}_pasted_log_{timestamp}.txt"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(log_content)
        
        log_entries = parse_log(log_content)
        
        # Handle error if no entries found
        if not log_entries:
            flash('No valid log entries found in the content. Please check the format.')
            return redirect(url_for('index'))
            
        try:
            analysis = analyze_log_entries(log_entries)
            recommendations = generate_recommendations(log_entries, analysis)
            
            # Save the analysis results
            result_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_analysis.json")
            with open(result_path, 'w') as f:
                # Use a default JSON encoder to handle sets
                class SetEncoder(json.JSONEncoder):
                    def default(self, obj):
                        if isinstance(obj, set):
                            return list(obj)
                        return json.JSONEncoder.default(self, obj)
                
                json.dump({
                    'entries': log_entries,
                    'analysis': analysis,
                    'recommendations': recommendations,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'filename': filename
                }, f, indent=2, cls=SetEncoder)
            
            return redirect(url_for('show_analysis', filename=filename))
        except Exception as analysis_error:
            logger.exception(f"Error analyzing log content: {str(analysis_error)}")
            flash(f'Error analyzing log content: {str(analysis_error)}')
            
            # Even if analysis fails, we can still show the raw entries
            result_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_basic_analysis.json")
            with open(result_path, 'w') as f:
                json.dump({
                    'entries': log_entries,
                    'analysis': {
                        'critical_issues_count': len([e for e in log_entries if e.get('severity', 0) >= 3]),
                        'problematic_components': [],
                        'most_common_errors': []
                    },
                    'recommendations': [
                        {'title': 'Review Log Content', 
                         'description': 'Advanced analysis failed, but you can still review log entries.',
                         'steps': ['Check timestamps', 'Look for ERROR or CRITICAL entries', 'Review components with most issues']}
                    ],
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'filename': filename
                }, f, indent=2)
            
            return redirect(url_for('show_analysis', filename=filename))
            
    except Exception as e:
        logger.exception(f"Error processing log content: {str(e)}")
        flash(f'Error processing log content: {str(e)}')
        return redirect(url_for('index'))

@app.route('/analyze_url', methods=['POST'])
@login_required
def analyze_url():
    if 'logurl' not in request.form or not request.form['logurl'].strip():
        flash('No URL provided')
        return redirect(url_for('index'))
    
    log_url = request.form['logurl'].strip()
    
    # Check if it's a Jenkins URL but missing /consoleText
    # Support various Jenkins URL patterns
    jenkins_patterns = [
        re.compile(r'https?://[^/]+/[^/]+/job/[^/]+/\d+/?$'),          # Basic Jenkins job URL
        re.compile(r'https?://[^/]+/jenkins/job/[^/]+/\d+/?$'),        # Jenkins with /jenkins prefix
        re.compile(r'https?://[^/]+/[^/]+/view/[^/]+/job/[^/]+/\d+/?$'), # Jenkins view URL
        re.compile(r'https?://[^/]+/job/[^/]+/\d+/?$'),                # Root level job URL
        # Support multi-level pipeline jobs
        re.compile(r'https?://[^/]+/(?:[^/]+/)*job/[^/]+/job/[^/]+/\d+/?$')
    ]
    
    is_jenkins_url = any(pattern.match(log_url) for pattern in jenkins_patterns)
    if is_jenkins_url and 'consoleText' not in log_url:
        # Add /consoleText if not already present
        if not log_url.endswith('/'):
            log_url += '/'
        if not log_url.endswith('consoleText'):
            log_url += 'consoleText'
        logger.info(f"Modified Jenkins URL to: {log_url}")
        flash(f"Added '/consoleText' to Jenkins URL for log retrieval", "info")
    
    # Load system settings
    settings = load_settings()
    
    # Check for SSL verification settings from form or use system defaults
    if 'verify_ssl' in request.form:
        # User explicitly set verification in the form
        verify_ssl = 'verify_ssl' in request.form and request.form.get('verify_ssl') == 'on'
    else:
        # Use system default
        verify_ssl = settings['ssl']['verify_ssl_by_default']
    
    # Check if user is allowed to disable SSL verification
    if not verify_ssl and not settings['ssl']['allow_insecure_ssl'] and session.get('role') != ROLE_ADMIN:
        # Non-admin users cannot disable SSL verification if system setting disallows it
        logger.warning("Non-admin user attempted to disable SSL verification, but system settings disallow it")
        flash("SSL verification cannot be disabled due to system security settings", "warning")
        verify_ssl = True
    
    # Log the verification setting for debugging
    logger.info(f"SSL verification setting: {'enabled' if verify_ssl else 'disabled'}")
    if not verify_ssl:
        logger.warning("SSL certificate verification has been disabled by user request")
    
    # Determine CA bundle path based on form input or system settings
    ca_bundle_path = None
    cert_mode = request.form.get('ca_bundle') if 'ca_bundle' in request.form else settings['ssl']['default_cert_mode']
    
    if cert_mode == 'system':
        # System certificates - check if the system has certificate issues
        try:
            # Try to detect the CA certificates path
            import ssl
            import certifi
            
            # Common system certificate paths in different distributions
            system_cert_paths = [
                "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # Red Hat / CentOS
                "/etc/pki/tls/certs/ca-bundle.crt",                   # Red Hat / CentOS alternative
                "/etc/pki/CA/certs",                                  # Red Hat / CentOS directory
                "/etc/ssl/certs/ca-certificates.crt",                 # Debian / Ubuntu
                "/etc/ssl/certs",                                     # Debian / Ubuntu directory
                "/etc/certificates",                                  # Generic path
                "/usr/local/share/certs",                             # FreeBSD
                "/usr/local/etc/ssl/certs",                           # OpenBSD
            ]
            
            # Log the certificates path being used
            default_certs = ssl.get_default_verify_paths()
            certifi_path = certifi.where()
            
            logger.info(f"System using cert paths: {default_certs}")
            logger.info(f"Certifi path: {certifi_path}")
            
            # Find existing system certificate paths
            existing_paths = [path for path in system_cert_paths if os.path.exists(path)]
            logger.info(f"Found system certificate paths: {existing_paths}")
            
            # If system paths exist but aren't being used, suggest them
            if existing_paths:
                first_path = existing_paths[0]
                if os.path.isdir(first_path):
                    logger.info(f"Found system certificate directory: {first_path}")
                    flash(f"Info: If you have SSL issues, try using system certificates from: {first_path}", "info")
                else:
                    logger.info(f"Found system certificate bundle: {first_path}")
                    flash(f"Info: If you have SSL issues, try setting custom CA bundle path to: {first_path}", "info")
            # If no system paths but certifi exists, suggest it
            elif os.path.exists(certifi_path):
                logger.info(f"No system cert paths found, but certifi available at {certifi_path}")
                flash(f"Info: Your system is using {default_certs.cafile or 'default certificates'}. " +
                      f"If you have SSL issues, try setting custom CA bundle path to: {certifi_path}", "info")
        except (ImportError, Exception) as cert_check_error:
            logger.warning(f"Could not check certificate paths: {str(cert_check_error)}")
    
    elif cert_mode == 'custom':
        # Custom CA bundle path from form or settings
        if 'custom_ca_path' in request.form and request.form.get('custom_ca_path').strip():
            ca_bundle_path = request.form.get('custom_ca_path').strip()
        else:
            # Use system default custom path
            ca_bundle_path = settings['ssl']['default_ca_path']
            logger.info(f"Using system default CA bundle path: {ca_bundle_path}")
            
        # Verify the CA bundle path exists
        if not os.path.exists(ca_bundle_path):
            flash(f'Custom CA bundle path does not exist: {ca_bundle_path}')
            return redirect(url_for('index'))
    
    elif cert_mode == 'certifi':
        # Use Python's certifi package
        try:
            import certifi
            ca_bundle_path = certifi.where()
            logger.info(f"Using certifi path: {ca_bundle_path}")
        except ImportError:
            flash(f'Certifi package not installed. Please install it or choose a different certificate mode.', 'error')
            return redirect(url_for('index'))
    
    try:
        # Fetch the content from the URL with appropriate SSL settings
        if ca_bundle_path:
            # Handle both file paths and directory paths
            if os.path.isdir(ca_bundle_path):
                logger.info(f"Certificate path is a directory: {ca_bundle_path}")
                
                # For Red Hat/CentOS, find individual .pem files in the directory
                # and create a temporary CA bundle by concatenating them
                try:
                    # Find all .pem and .crt files in the directory
                    cert_files = []
                    for filename in os.listdir(ca_bundle_path):
                        if filename.endswith('.pem') or filename.endswith('.crt'):
                            cert_files.append(os.path.join(ca_bundle_path, filename))
                    
                    logger.info(f"Found {len(cert_files)} certificate files in {ca_bundle_path}")
                    
                    if cert_files:
                        # Create a temporary bundle file by concatenating all certificate files
                        temp_bundle_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_ca_bundle_{datetime.now().strftime('%Y%m%d%H%M%S')}.pem")
                        with open(temp_bundle_path, 'w') as temp_bundle:
                            for cert_file in cert_files:
                                try:
                                    with open(cert_file, 'r') as cf:
                                        temp_bundle.write(cf.read())
                                        temp_bundle.write('\n')
                                except Exception as read_err:
                                    logger.warning(f"Error reading certificate file {cert_file}: {str(read_err)}")
                        
                        logger.info(f"Created temporary CA bundle at {temp_bundle_path} from {len(cert_files)} certificate files")
                        flash(f"Using {len(cert_files)} certificates from {ca_bundle_path}", "info")
                        response = requests.get(log_url, timeout=30, verify=temp_bundle_path)
                    else:
                        # Look for common bundle filenames in the directory
                        bundle_filenames = ['ca-bundle.crt', 'ca-certificates.crt', 'ca-roots.crt', 'cacert.pem']
                        bundle_file = None
                        
                        for filename in bundle_filenames:
                            potential_path = os.path.join(ca_bundle_path, filename)
                            if os.path.exists(potential_path):
                                bundle_file = potential_path
                                break
                        
                        if bundle_file:
                            logger.info(f"Found bundle file in directory: {bundle_file}")
                            flash(f"Using certificate bundle: {bundle_file}", "info")
                            response = requests.get(log_url, timeout=30, verify=bundle_file)
                        elif verify_ssl:  # Only fall back if verification is required
                            # If no certificate files found, try with certifi as fallback
                            import certifi
                            certifi_path = certifi.where()
                            logger.info(f"No certificate files found in {ca_bundle_path}, falling back to certifi: {certifi_path}")
                            flash(f"No certificate files found in {ca_bundle_path}, using certifi instead", "warning")
                            response = requests.get(log_url, timeout=30, verify=certifi_path)
                        else:
                            # If verification is disabled, proceed without verification
                            logger.warning(f"No certificate files found and verification is disabled, proceeding without verification")
                            flash(f"No certificate files found in {ca_bundle_path}, proceeding without verification", "warning")
                            response = requests.get(log_url, timeout=30, verify=False)
                except Exception as dir_err:
                    logger.warning(f"Error processing certificate directory {ca_bundle_path}: {str(dir_err)}")
                    
                    if verify_ssl:
                        # Try with certifi as fallback if verification is required
                        import certifi
                        certifi_path = certifi.where()
                        logger.info(f"Falling back to certifi: {certifi_path}")
                        flash(f"Error processing certificates in {ca_bundle_path}, using certifi instead", "warning")
                        response = requests.get(log_url, timeout=30, verify=certifi_path)
                    else:
                        # If verification is disabled, proceed without verification
                        logger.warning(f"Error processing certificates and verification is disabled, proceeding without verification")
                        flash(f"Error processing certificates, proceeding without verification", "warning")
                        response = requests.get(log_url, timeout=30, verify=False)
            else:
                # Regular file path, but only verify if the verification flag is enabled
                if verify_ssl:
                    response = requests.get(log_url, timeout=30, verify=ca_bundle_path)
                else:
                    logger.warning(f"Using file path {ca_bundle_path} but verification is disabled, proceeding without verification")
                    response = requests.get(log_url, timeout=30, verify=False)
        else:
            # Use system certificates if verification is enabled, otherwise disable verification
            if verify_ssl:
                response = requests.get(log_url, timeout=30, verify=True)
            else:
                logger.warning("Proceeding without SSL certificate verification")
                response = requests.get(log_url, timeout=30, verify=False)
        
        # Check if the request was successful
        if response.status_code != 200:
            flash(f'Failed to fetch log from URL: HTTP {response.status_code}')
            return redirect(url_for('index'))
        
        # Get the log content
        log_content = response.text
        
        # Save the content to a file with user prefix and URL info
        user_id = session['user_id']
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        
        # Extract filename from URL or use generic name
        url_parts = log_url.split('/')
        original_filename = url_parts[-1] if url_parts[-1] else 'remote_log'
        safe_filename = secure_filename(original_filename)
        
        filename = f"{user_id}_url_{timestamp}_{safe_filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(log_content)
        
        log_entries = parse_log(log_content)
        
        # Handle error if no entries found
        if not log_entries:
            flash('No valid log entries found in the content from URL. Please check the format.')
            return redirect(url_for('index'))
            
        try:
            analysis = analyze_log_entries(log_entries)
            recommendations = generate_recommendations(log_entries, analysis)
            
            # Save the analysis results
            result_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_analysis.json")
            with open(result_path, 'w') as f:
                # Use a default JSON encoder to handle sets
                class SetEncoder(json.JSONEncoder):
                    def default(self, obj):
                        if isinstance(obj, set):
                            return list(obj)
                        return json.JSONEncoder.default(self, obj)
                
                # Create analysis result
                analysis_result = {
                    'entries': log_entries,
                    'analysis': analysis,
                    'recommendations': recommendations,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'filename': filename,
                    'original_filename': original_filename,
                    'source_url': log_url,
                    'user_id': user_id,
                    'username': session.get('username', 'Unknown')
                }
                
                json.dump(analysis_result, f, indent=2, cls=SetEncoder)
                
                # Add to user's logs
                try:
                    with open(app.config['USERS_FILE'], 'r') as users_f:
                        users_data = json.load(users_f)
                        
                    for user in users_data['users']:
                        if user['id'] == user_id:
                            user['logs'].append({
                                'filename': filename,
                                'original_filename': original_filename,
                                'source_url': log_url,
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'critical_issues': analysis['critical_issues_count']
                            })
                            break
                            
                    with open(app.config['USERS_FILE'], 'w') as users_f:
                        json.dump(users_data, users_f, indent=2)
                except Exception as e:
                    logger.warning(f"Error updating user logs: {str(e)}")
            
            return redirect(url_for('show_analysis', filename=filename))
        except Exception as analysis_error:
            logger.exception(f"Error analyzing log from URL: {str(analysis_error)}")
            flash(f'Error analyzing log from URL: {str(analysis_error)}')
            
            # Even if analysis fails, we can still show the raw entries
            result_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_basic_analysis.json")
            with open(result_path, 'w') as f:
                json.dump({
                    'entries': log_entries,
                    'analysis': {
                        'critical_issues_count': len([e for e in log_entries if e.get('severity', 0) >= 3]),
                        'problematic_components': [],
                        'most_common_errors': [],
                        'source_url': log_url
                    },
                    'recommendations': [
                        {'title': 'Review Log Content from URL', 
                         'description': f'Advanced analysis failed for log from {log_url}',
                         'steps': ['Check timestamps', 'Look for ERROR or CRITICAL entries', 'Review components with most issues']}
                    ],
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'filename': filename,
                    'original_filename': original_filename,
                    'source_url': log_url,
                    'user_id': user_id,
                    'username': session.get('username', 'Unknown'),
                    'is_basic_analysis': True
                }, f, indent=2)
            
            return redirect(url_for('show_analysis', filename=filename))
            
    except requests.exceptions.SSLError as ssl_error:
        logger.exception(f"SSL certificate verification failed: {str(ssl_error)}")
        
        # Provide a more helpful error message with instructions
        error_msg = f"SSL certificate verification failed: {str(ssl_error)}"
        suggestion = (
            "You can try one of the following solutions:\n"
            "1. Use system certificates (already selected by default)\n"
            "2. Provide a custom CA bundle path\n"
            "3. Uncheck 'Verify SSL certificates' (only if you trust the source)"
        )
        
        flash(f"{error_msg}\n\n{suggestion}")
        return redirect(url_for('index'))
    except requests.RequestException as req_error:
        logger.exception(f"Error fetching log from URL: {str(req_error)}")
        flash(f'Error fetching log from URL: {str(req_error)}')
        return redirect(url_for('index'))
    except Exception as e:
        logger.exception(f"Error processing log from URL: {str(e)}")
        flash(f'Error processing log from URL: {str(e)}')
        return redirect(url_for('index'))

@app.route('/analysis/<filename>')
@login_required
def show_analysis(filename):
    # Try both the regular and basic analysis files
    result_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_analysis.json")
    basic_result_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_basic_analysis.json")
    
    if os.path.exists(result_path):
        path_to_use = result_path
    elif os.path.exists(basic_result_path):
        path_to_use = basic_result_path
    else:
        flash('Analysis not found')
        return redirect(url_for('index'))
    
    try:
        with open(path_to_use, 'r') as f:
            analysis_data = json.load(f)
        
        # Check if user has access to this analysis
        user_id = session['user_id']
        role = session.get('role', ROLE_USER)
        
        # Allow access if user is admin or the file belongs to the user
        if role == ROLE_ADMIN or ('user_id' in analysis_data and analysis_data['user_id'] == user_id):
            # Add enumerate function to Jinja environment
            return render_template('analysis.html', 
                                  entries=analysis_data['entries'], 
                                  analysis=analysis_data['analysis'],
                                  recommendations=analysis_data['recommendations'],
                                  filename=filename,
                                  original_filename=analysis_data.get('original_filename', filename),
                                  source_url=analysis_data.get('source_url', ''),
                                  user=session,
                                  enumerate=enumerate)
        else:
            flash('You do not have permission to view this analysis')
            return redirect(url_for('index'))
    except Exception as e:
        logger.exception(f"Error loading analysis file: {str(e)}")
        flash(f'Error loading analysis file: {str(e)}')
        return redirect(url_for('index'))

@app.route('/api/logs', methods=['GET'])
@login_required
def list_logs():
    logs = []
    user_id = session['user_id']
    role = session.get('role', ROLE_USER)
    
    try:
        # For admin users, show all logs
        # For regular users, show only their logs
        if role == ROLE_ADMIN:
            # List all analysis files
            for filename in os.listdir(app.config['UPLOAD_FOLDER']):
                if filename.endswith('_analysis.json') or filename.endswith('_basic_analysis.json'):
                    try:
                        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'r') as f:
                            data = json.load(f)
                            logs.append({
                                'filename': data.get('filename', filename.replace('_analysis.json', '').replace('_basic_analysis.json', '')),
                                'timestamp': data.get('timestamp', 'Unknown date'),
                                'critical_issues_count': data.get('analysis', {}).get('critical_issues_count', 0),
                                'is_basic': filename.endswith('_basic_analysis.json'),
                                'username': data.get('username', 'Unknown'),
                                'user_id': data.get('user_id', 'Unknown'),
                                'original_filename': data.get('original_filename', data.get('filename', ''))
                            })
                    except Exception as e:
                        logger.warning(f"Error loading log file {filename}: {str(e)}")
                        continue
        else:
            # Get logs from user data for regular users
            try:
                with open(app.config['USERS_FILE'], 'r') as f:
                    users_data = json.load(f)
                
                user = next((u for u in users_data['users'] if u['id'] == user_id), None)
                if user and 'logs' in user:
                    for log in user['logs']:
                        filename = log['filename']
                        result_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_analysis.json")
                        basic_result_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_basic_analysis.json")
                        
                        if os.path.exists(result_path) or os.path.exists(basic_result_path):
                            logs.append({
                                'filename': filename,
                                'timestamp': log.get('timestamp', 'Unknown date'),
                                'critical_issues_count': log.get('critical_issues', 0),
                                'is_basic': log.get('is_basic_analysis', False),
                                'original_filename': log.get('original_filename', filename)
                            })
            except Exception as e:
                logger.warning(f"Error loading user logs: {str(e)}")
    except Exception as e:
        logger.error(f"Error listing logs: {str(e)}")
    
    return jsonify(logs)

@app.route('/logs')
@login_required
def show_logs():
    return render_template('logs.html', user=session)

@app.route('/my-logs')
@login_required
def my_logs():
    return render_template('my_logs.html', user=session)

@app.route('/rawlog/<filename>')
@login_required
def raw_log(filename):
    """Show the raw log file content with line numbers"""
    # Check for existence of the file
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        flash('Log file not found')
        return redirect(url_for('index'))
    
    # Check user permissions
    user_id = session['user_id']
    role = session.get('role', ROLE_USER)
    
    # Check if filename starts with user_id or user is admin
    if not role == ROLE_ADMIN and not filename.startswith(f"{user_id}_"):
        flash('You do not have permission to view this log')
        return redirect(url_for('index'))
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            log_content = f.read()
        
        # Get log lines with line numbers
        log_lines = log_content.splitlines()
        
        return render_template('raw_log.html', 
                             filename=filename,
                             log_lines=log_lines,
                             line_count=len(log_lines),
                             user=session)
    except Exception as e:
        flash(f'Error reading log file: {str(e)}')
        return redirect(url_for('index'))

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for analyzing logs from external sources like Jenkins"""
    # Check if API key provided (basic auth for now)
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            'status': 'error',
            'message': 'Authentication required'
        }), 401
    
    api_key = auth_header.split(' ')[1]
    
    # For demonstration, use a simple API key - in production, use a secure method
    if api_key != 'jenkins-analyzer-api-key':
        return jsonify({
            'status': 'error',
            'message': 'Invalid API key'
        }), 403
    
    # Get log content and metadata
    data = request.json
    if not data or 'log_content' not in data:
        return jsonify({
            'status': 'error',
            'message': 'Log content is required'
        }), 400
    
    log_content = data['log_content']
    job_name = data.get('job_name', 'unknown-job')
    build_number = data.get('build_number', 'unknown-build')
    source_url = data.get('source_url', '')
    
    try:
        # Save log to file with API prefix to distinguish from UI uploads
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f"api_{timestamp}_{secure_filename(job_name)}_{build_number}.txt"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(log_content)
        
        # Process log entries
        log_entries = parse_log(log_content)
        
        if not log_entries:
            return jsonify({
                'status': 'warning',
                'message': 'No valid log entries found'
            }), 200
        
        # Analyze the entries
        try:
            analysis = analyze_log_entries(log_entries)
            recommendations = generate_recommendations(log_entries, analysis)
            
            # Save analysis to file
            result_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_analysis.json")
            
            with open(result_path, 'w') as f:
                class SetEncoder(json.JSONEncoder):
                    def default(self, obj):
                        if isinstance(obj, set):
                            return list(obj)
                        return json.JSONEncoder.default(self, obj)
                
                # Create analysis result with API source info
                analysis_result = {
                    'entries': log_entries,
                    'analysis': analysis,
                    'recommendations': recommendations,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'filename': filename,
                    'original_filename': f"{job_name}_{build_number}",
                    'source_url': source_url,
                    'source': 'jenkins-api',
                    'username': 'Jenkins API',
                    'is_api_source': True
                }
                
                json.dump(analysis_result, f, indent=2, cls=SetEncoder)
            
            # Create the summary response
            critical_count = analysis['critical_issues_count']
            error_count = analysis['error_by_level'].get('ERROR', 0)
            warning_count = analysis['error_by_level'].get('WARNING', 0) + analysis['error_by_level'].get('WARN', 0)
            
            # List of error patterns found
            patterns_found = [{'name': p['pattern_name'], 'severity': p['severity'], 
                             'description': p['description'], 'suggestion': p['suggestion']} 
                             for p in analysis['pattern_matches']]
            
            # Create a viewer URL for this analysis
            viewer_url = url_for('show_analysis', filename=filename, _external=True)
            
            return jsonify({
                'status': 'success',
                'analysis_id': filename,
                'counts': {
                    'critical': critical_count,
                    'error': error_count,
                    'warning': warning_count,
                    'total': len(log_entries)
                },
                'patterns_found': patterns_found,
                'main_issue': analysis['most_common_errors'][0] if analysis['most_common_errors'] else None,
                'recommendations': recommendations,
                'viewer_url': viewer_url
            })
            
        except Exception as analysis_error:
            logger.exception(f"API error: {str(analysis_error)}")
            
            # Return basic info even on error
            return jsonify({
                'status': 'error',
                'message': f'Error analyzing log: {str(analysis_error)}',
                'viewer_url': url_for('show_analysis', filename=filename, _external=True)
            }), 500
            
    except Exception as e:
        logger.exception(f"API error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Server error: {str(e)}'
        }), 500

@app.route('/api/logs/<filename>', methods=['DELETE'])
@login_required
def delete_log(filename):
    """Delete a log analysis file and its associated raw log file"""
    user_id = session['user_id']
    role = session.get('role', ROLE_USER)
    
    try:
        # Check if the user has permission to delete this log
        if role != ROLE_ADMIN:
            # For regular users, check if the log belongs to them
            with open(app.config['USERS_FILE'], 'r') as f:
                users_data = json.load(f)
            
            user = next((u for u in users_data['users'] if u['id'] == user_id), None)
            if not user or 'logs' not in user:
                return jsonify({'success': False, 'message': 'Permission denied'}), 403
            
            # Check if the log is in the user's logs
            user_log = next((log for log in user['logs'] if log['filename'] == filename), None)
            if not user_log:
                return jsonify({'success': False, 'message': 'Log not found or permission denied'}), 404
        
        # Delete the analysis files
        analysis_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_analysis.json")
        basic_analysis_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_basic_analysis.json")
        raw_log_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        deleted_files = []
        
        if os.path.exists(analysis_path):
            os.remove(analysis_path)
            deleted_files.append(analysis_path)
        
        if os.path.exists(basic_analysis_path):
            os.remove(basic_analysis_path)
            deleted_files.append(basic_analysis_path)
        
        # Delete the raw log file if it exists
        if os.path.exists(raw_log_path):
            os.remove(raw_log_path)
            deleted_files.append(raw_log_path)
        
        # If the user is not an admin, update their logs list
        if role != ROLE_ADMIN and user and 'logs' in user:
            user['logs'] = [log for log in user['logs'] if log['filename'] != filename]
            
            # Save the updated user data
            with open(app.config['USERS_FILE'], 'w') as f:
                json.dump(users_data, f, indent=2)
        
        return jsonify({
            'success': True, 
            'message': f'Log analysis deleted successfully', 
            'deleted_files': deleted_files
        })
    
    except Exception as e:
        logger.error(f"Error deleting log {filename}: {str(e)}")
        return jsonify({'success': False, 'message': f'Error deleting log: {str(e)}'}), 500

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_password or not new_password or not confirm_password:
            flash('Please fill in all password fields')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New password and confirmation do not match')
            return render_template('change_password.html')
        
        if len(new_password) < 8:
            flash('New password must be at least 8 characters long')
            return render_template('change_password.html')
        
        try:
            # Get user data
            with open(app.config['USERS_FILE'], 'r') as file_handle:
                users_data = json.load(file_handle)
            
            # Find current user
            user_id = session.get('user_id')
            user = next((u for u in users_data['users'] if u['id'] == user_id), None)
            
            if not user:
                flash('User not found')
                return render_template('change_password.html')
            
            # Verify current password
            current_password_hash = hashlib.sha256(current_password.encode()).hexdigest()
            if current_password_hash != user['password_hash']:
                flash('Current password is incorrect')
                return render_template('change_password.html')
            
            # Update password
            new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
            user['password_hash'] = new_password_hash
            
            # Save updated user data
            with open(app.config['USERS_FILE'], 'w') as file_handle:
                json.dump(users_data, file_handle, indent=2)
            
            flash('Password changed successfully', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            flash(f'Error changing password: {str(e)}')
            return render_template('change_password.html')
    
    return render_template('change_password.html')

# View analysis for a specific log file (test route)
@app.route('/test_analyze', methods=['GET'])
def test_analyze():
    """Test route to analyze the sample Jenkins log file"""
    try:
        # Read the sample log file
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs/sample_jenkins_build.log')
        with open(log_path, 'r', encoding='utf-8') as f:
            log_content = f.read()
        
        # Parse the log
        entries = parse_log(log_content)
        
        # Analyze the entries
        analysis = analyze_log_entries(entries)
        
        # Generate recommendations
        recommendations = generate_recommendations(entries, analysis)
        
        # Match patterns against entries
        for entry in entries:
            # Check if this entry matches any pattern
            for pattern_match in analysis.get('pattern_matches', []):
                if pattern_match.get('line_number') == entry.get('line_number'):
                    entry['matched_pattern'] = {
                        'id': pattern_match.get('pattern_id'),
                        'name': pattern_match.get('pattern_name'),
                        'pattern': pattern_match.get('pattern'),
                        'severity': pattern_match.get('severity'),
                        'description': pattern_match.get('description'),
                        'suggestion': pattern_match.get('suggestion')
                    }
                    # Check if this might be a false positive
                    if entry.get('component') in ['Unknown', None] or '/' in entry.get('message') or '\\' in entry.get('message'):
                        entry['false_positive'] = True
                    break
        
        # Render the analysis template
        return render_template('analysis.html', 
                               entries=entries, 
                               analysis=analysis, 
                               recommendations=recommendations,
                               original_filename='sample_jenkins_build.log',
                               log_id='sample_jenkins_build.log')
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f"Error analyzing log: {str(e)}")
        return redirect(url_for('index'))

# Admin Settings Management
@app.route('/admin/settings', methods=['GET'])
@admin_required
def admin_settings():
    """Admin settings page for system configuration"""
    try:
        # Get system certificate information
        ssl_info = {}
        try:
            import ssl
            import certifi
            default_certs = ssl.get_default_verify_paths()
            ssl_info = {
                'cafile': default_certs.cafile,
                'capath': default_certs.capath,
                'certifi': certifi.where()
            }
        except Exception as e:
            logger.warning(f"Error getting SSL certificate info: {str(e)}")
            ssl_info = {
                'cafile': 'Error getting cafile',
                'capath': 'Error getting capath',
                'certifi': 'Error getting certifi path'
            }
        
        # Common certificate paths to check
        system_cert_paths = [
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # Red Hat / CentOS
            "/etc/pki/tls/certs/ca-bundle.crt",                   # Red Hat / CentOS alternative
            "/etc/pki/CA/certs",                                  # Red Hat / CentOS directory
            "/etc/ssl/certs/ca-certificates.crt",                 # Debian / Ubuntu
            "/etc/ssl/certs",                                     # Debian / Ubuntu directory
            "/etc/certificates",                                  # Generic path
            "/usr/local/share/certs",                             # FreeBSD
            "/usr/local/etc/ssl/certs",                           # OpenBSD
        ]
        
        # Check if each path exists
        path_exists = {}
        for path in system_cert_paths:
            path_exists[path] = os.path.exists(path)
        
        # Load settings
        settings = load_settings()
        
        return render_template('admin_settings.html', 
                              ssl_info=ssl_info,
                              system_cert_paths=system_cert_paths,
                              path_exists=path_exists,
                              settings=settings)
    except Exception as e:
        logger.exception(f"Error loading admin settings: {str(e)}")
        flash(f"Error loading settings: {str(e)}")
        return redirect(url_for('index'))

@app.route('/admin/save_ssl_settings', methods=['POST'])
@admin_required
def save_ssl_settings():
    """Save SSL certificate settings"""
    try:
        # Load current settings
        settings = load_settings()
        
        # Update SSL settings
        settings['ssl']['default_cert_mode'] = request.form.get('default_cert_mode', 'system')
        settings['ssl']['default_ca_path'] = request.form.get('default_ca_path', '')
        settings['ssl']['allow_insecure_ssl'] = 'allow_insecure_ssl' in request.form
        settings['ssl']['verify_ssl_by_default'] = 'verify_ssl_by_default' in request.form
        
        # Save settings
        save_settings(settings)
        
        flash("SSL settings updated successfully")
        return redirect(url_for('admin_settings'))
    except Exception as e:
        logger.exception(f"Error saving SSL settings: {str(e)}")
        flash(f"Error saving settings: {str(e)}")
        return redirect(url_for('admin_settings'))

@app.route('/admin/save_general_settings', methods=['POST'])
@admin_required
def save_general_settings():
    """Save general system settings"""
    try:
        # Load current settings
        settings = load_settings()
        
        # Update general settings
        settings['general']['max_upload_size'] = int(request.form.get('max_upload_size', 16))
        settings['general']['session_lifetime'] = int(request.form.get('session_lifetime', 24))
        settings['general']['enable_url_analysis'] = 'enable_url_analysis' in request.form
        settings['general']['enable_guest_access'] = 'enable_guest_access' in request.form
        
        # Save settings
        save_settings(settings)
        
        # Update app configuration
        app.config['MAX_CONTENT_LENGTH'] = settings['general']['max_upload_size'] * 1024 * 1024
        app.config['SESSION_LIFETIME'] = timedelta(hours=settings['general']['session_lifetime'])
        
        flash("General settings updated successfully")
        return redirect(url_for('admin_settings'))
    except Exception as e:
        logger.exception(f"Error saving general settings: {str(e)}")
        flash(f"Error saving settings: {str(e)}")
        return redirect(url_for('admin_settings'))

@app.route('/admin/test_ssl_connection')
@admin_required
def test_ssl_connection():
    """Test SSL connection with specified certificate settings"""
    try:
        # Get test parameters
        mode = request.args.get('mode', 'system')
        path = request.args.get('path', '')
        verify = request.args.get('verify', 'true') == 'true'
        
        # Test URL (default to Google as it should be generally accessible)
        test_url = request.args.get('url', 'https://www.google.com')
        
        # Determine verification parameter
        if not verify:
            # If verification is disabled
            verify_param = False
        elif mode == 'custom' and path:
            # If custom path provided and exists
            if os.path.exists(path):
                verify_param = path
            else:
                return jsonify({
                    'success': False,
                    'error': f'Custom certificate path does not exist: {path}'
                })
        elif mode == 'certifi':
            # Use certifi
            import certifi
            verify_param = certifi.where()
        else:
            # System certificates (default)
            verify_param = True
        
        # Perform the test request
        response = requests.get(test_url, timeout=10, verify=verify_param)
        
        return jsonify({
            'success': True,
            'status': response.status_code,
            'url': test_url,
            'verify_mode': 'Enabled' if verify else 'Disabled',
            'cert_path': str(verify_param) if isinstance(verify_param, str) else 'System certificates' if verify_param else 'Verification disabled'
        })
    except requests.exceptions.SSLError as ssl_err:
        logger.error(f"SSL error during test connection: {str(ssl_err)}")
        return jsonify({
            'success': False,
            'error': f'SSL Certificate Error: {str(ssl_err)}'
        })
    except Exception as e:
        logger.error(f"Error during test connection: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

# Helper functions for settings
def load_settings():
    """Load system settings from file"""
    try:
        # Check if settings file exists
        if os.path.exists(app.config['SETTINGS_FILE']):
            with open(app.config['SETTINGS_FILE'], 'r') as f:
                return json.load(f)
        else:
            # Create default settings
            default_settings = {
                'ssl': {
                    'default_cert_mode': 'system',
                    'default_ca_path': '/etc/pki/CA/certs',
                    'allow_insecure_ssl': True,
                    'verify_ssl_by_default': True
                },
                'general': {
                    'max_upload_size': 16,
                    'session_lifetime': 24,
                    'enable_url_analysis': True,
                    'enable_guest_access': False
                }
            }
            
            # Save default settings
            with open(app.config['SETTINGS_FILE'], 'w') as f:
                json.dump(default_settings, f, indent=2)
            
            return default_settings
    except Exception as e:
        logger.error(f"Error loading settings: {str(e)}")
        # Return default settings
        return {
            'ssl': {
                'default_cert_mode': 'system',
                'default_ca_path': '',
                'allow_insecure_ssl': True,
                'verify_ssl_by_default': True
            },
            'general': {
                'max_upload_size': 16,
                'session_lifetime': 24,
                'enable_url_analysis': True,
                'enable_guest_access': False
            }
        }

def save_settings(settings):
    """Save system settings to file"""
    try:
        with open(app.config['SETTINGS_FILE'], 'w') as f:
            json.dump(settings, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving settings: {str(e)}")
        return False

# Fix pattern route - redirects to edit_pattern
@app.route('/fix_pattern', methods=['POST'])
@login_required
def fix_pattern():
    """Fix a pattern from analysis page"""
    try:
        pattern_id = int(request.form.get('pattern_id'))
        pattern_name = request.form.get('pattern_name')
        pattern_regex = request.form.get('pattern_regex')
        pattern_type = request.form.get('pattern_type')
        severity = request.form.get('severity')
        description = request.form.get('description')
        suggestion = request.form.get('suggestion')
        exclude_paths = 'exclude_paths' in request.form
        exclude_timestamp = 'exclude_timestamp' in request.form
        
        # Verify user is admin
        if session.get('role') != ROLE_ADMIN:
            flash("Only administrators can edit patterns")
            return redirect(url_for('show_patterns'))
        
        # Load current patterns
        with open(app.config['PATTERNS_FILE'], 'r') as f:
            patterns = json.load(f)
        
        # Find and update the pattern
        pattern_found = False
        for category in patterns.values():
            for pattern in category:
                if pattern['id'] == pattern_id:
                    pattern['name'] = pattern_name
                    pattern['pattern'] = pattern_regex
                    pattern['severity'] = severity
                    pattern['description'] = description
                    pattern['suggestion'] = suggestion
                    pattern['exclude_paths'] = exclude_paths
                    pattern['exclude_timestamp'] = exclude_timestamp
                    pattern['updated_by'] = session.get('username', 'Unknown')
                    pattern['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    pattern_found = True
                    break
            if pattern_found:
                break
        
        if not pattern_found:
            flash(f"Pattern with ID {pattern_id} not found")
            return redirect(url_for('show_patterns'))
        
        # Save updated patterns
        with open(app.config['PATTERNS_FILE'], 'w') as f:
            json.dump(patterns, f, indent=2)
        
        # If the edit came from a log analysis, redirect back to the analysis
        log_id = request.form.get('log_id', '')
        analysis_id = request.form.get('analysis_id', '')
        
        if analysis_id:
            flash(f"Pattern '{pattern_name}' updated successfully")
            return redirect(url_for('show_analysis', filename=analysis_id))
        
        flash(f"Pattern '{pattern_name}' updated successfully")
        return redirect(url_for('show_patterns'))
        
    except Exception as e:
        flash(f"Error updating pattern: {str(e)}")
        return redirect(url_for('show_patterns'))

# API endpoints for pattern management and testing
@app.route('/api/pattern/<int:pattern_id>', methods=['GET'])
@login_required
def get_pattern_api(pattern_id):
    """Get pattern details via API"""
    try:
        # Load patterns
        with open(app.config['PATTERNS_FILE'], 'r') as f:
            patterns = json.load(f)
        
        # Search for pattern in both categories
        for pattern_type in ['jenkins_patterns', 'system_patterns']:
            for pattern in patterns[pattern_type]:
                if pattern['id'] == pattern_id:
                    pattern_data = {
                        'id': pattern['id'],
                        'name': pattern['name'],
                        'pattern': pattern['pattern'],
                        'severity': pattern['severity'],
                        'description': pattern['description'],
                        'suggestion': pattern['suggestion'],
                        'type': 'jenkins' if pattern_type == 'jenkins_patterns' else 'system',
                        'exclude_paths': pattern.get('exclude_paths', False),
                        'exclude_timestamp': pattern.get('exclude_timestamp', False)
                    }
                    return jsonify(pattern_data)
        
        return jsonify({'error': 'Pattern not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test_pattern', methods=['GET'])
@login_required
def test_pattern_api():
    """Test a regex pattern against log content"""
    try:
        regex = request.args.get('regex', '')
        log_id = request.args.get('log_id', '')
        
        if not regex:
            return jsonify({'success': False, 'error': 'No regex pattern provided'})
        
        # Get log content to test against
        if log_id:
            log_files = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if f.endswith('.txt') or f.endswith('.log') or '_analysis.json' in f]
            log_file = next((f for f in log_files if log_id in f), None)
            
            if not log_file:
                return jsonify({'success': False, 'error': 'Log file not found'})
                
            log_path = os.path.join(app.config['UPLOAD_FOLDER'], log_file)
            with open(log_path, 'r', errors='replace') as f:
                content = f.read()
        else:
            # Use sample log as fallback
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sample_log.txt'), 'r', errors='replace') as f:
                content = f.read()
        
        # Test pattern against log content
        try:
            pattern = re.compile(regex)
            matches = []
            
            # Check for matches in each line
            for line in content.splitlines():
                if pattern.search(line):
                    matches.append(line)
                    
            return jsonify({
                'success': True,
                'matches': matches[:100],  # Limit to 100 matches to avoid huge responses
                'match_count': len(matches)
            })
        except re.error as e:
            return jsonify({'success': False, 'error': f'Invalid regex pattern: {str(e)}'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/report_false_positive', methods=['POST'])
@login_required
def report_false_positive():
    """Report a false positive pattern match"""
    try:
        data = request.json
        pattern_id = data.get('pattern_id')
        entry_id = data.get('entry_id')
        log_id = data.get('log_id', '')
        
        if not pattern_id:
            return jsonify({'success': False, 'error': 'No pattern ID provided'})
        
        # Load patterns
        with open(app.config['PATTERNS_FILE'], 'r') as f:
            patterns = json.load(f)
        
        # Find pattern and update its false positive count
        pattern_found = False
        for pattern_type in ['jenkins_patterns', 'system_patterns']:
            for pattern in patterns[pattern_type]:
                if str(pattern['id']) == str(pattern_id):
                    # Increment false positive count
                    pattern['false_positive_count'] = pattern.get('false_positive_count', 0) + 1
                    
                    # Update effectiveness score
                    total_matches = pattern.get('match_count', 1)  # Avoid division by zero
                    false_positives = pattern.get('false_positive_count', 0)
                    pattern['effectiveness_score'] = max(0.0, 1.0 - (false_positives / total_matches))
                    
                    pattern_found = True
                    break
            if pattern_found:
                break
        
        if not pattern_found:
            return jsonify({'success': False, 'error': 'Pattern not found'})
        
        # Save updated patterns
        with open(app.config['PATTERNS_FILE'], 'w') as f:
            json.dump(patterns, f, indent=2)
        
        # Track the false positive to potentially suggest pattern improvements
        feedback_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pattern_feedback.json')
        
        try:
            with open(feedback_file, 'r') as f:
                feedback = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            feedback = {'false_positives': []}
        
        # Add feedback entry
        feedback['false_positives'].append({
            'pattern_id': pattern_id,
            'log_id': log_id,
            'entry_id': entry_id,
            'reported_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': session.get('user_id', 'anonymous')
        })
        
        # Save feedback
        with open(feedback_file, 'w') as f:
            json.dump(feedback, f, indent=2)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Update the extract_component function to improve component detection
def enhanced_extract_component(message, level=None):
    """Enhanced version of extract_component with better filtering for common false positives"""
    # Original component extraction logic
    original_component = extract_component(message, level)
    
    # Additional filtering for false positives
    if original_component:
        # Filter out components that are likely timestamps or dates
        timestamp_pattern = re.compile(r'^(\d{1,4}[-/\.]\d{1,2}[-/\.]\d{1,4}|\d{1,2}:\d{2}(:\d{2})?(\.\d+)?|\d{1,4}[-/\.]\d{1,2}[-/\.]\d{1,4}[T ]\d{1,2}:\d{2}(:\d{2})?)$')
        if timestamp_pattern.match(original_component):
            return None
        
        # Filter out Windows and Unix style paths as components
        path_pattern = re.compile(r'^([A-Za-z]:\\|/)(\w+|[.-]|\\|/)+$')
        if path_pattern.match(original_component):
            return None
        
        # Filter out common words that aren't useful components
        common_words = {'error', 'warning', 'info', 'exception', 'null', 'undefined', 'none'}
        if original_component.lower() in common_words:
            return None
        
        # Filter out components that are just numbers or units of measurement
        number_pattern = re.compile(r'^\d+(\.\d+)?(kb|mb|gb|ms|s|m|h|%)?$', re.IGNORECASE)
        if number_pattern.match(original_component):
            return None
    
    return original_component

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8082, debug=True)
