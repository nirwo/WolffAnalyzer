#!/bin/bash

# Make a backup of the original login.html
cp /code-claude/log_analyzer/templates/login.html /code-claude/log_analyzer/templates/login.html.bak

# Copy our modified login.html without default admin credentials
cp /code-claude/log_analyzer/login_fix.html /code-claude/log_analyzer/templates/login.html

# Copy the change_password.html template
cp /code-claude/log_analyzer/change_password.html /code-claude/log_analyzer/templates/change_password.html

# Copy the navbar.html template
cp /code-claude/log_analyzer/navbar.html /code-claude/log_analyzer/templates/navbar.html

# Restart the Flask application
pkill -f "python3 app.py" || true
cd /code-claude/log_analyzer && python3 app.py &

echo "Changes applied successfully!"
echo "1. Removed default admin credentials from login page"
echo "2. Added change password functionality"
echo "3. Added user dropdown menu with change password option"
echo "4. Restarted Flask application"
