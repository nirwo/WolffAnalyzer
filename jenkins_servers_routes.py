import json
import uuid
import requests
from flask import render_template, redirect, url_for, flash, request, jsonify, session
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            flash('Administrator access required', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def load_settings():
    """Load settings from settings.json file"""
    try:
        with open('settings.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading settings: {e}")
        return {}

def save_settings(settings):
    """Save settings to settings.json file"""
    try:
        with open('settings.json', 'w') as f:
            json.dump(settings, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving settings: {e}")
        return False

def jenkins_servers_routes(app):
    @app.route('/admin/jenkins-servers')
    @admin_required
    def jenkins_servers():
        """Display the Jenkins servers management page"""
        settings = load_settings()
        jenkins_servers = settings.get('jenkins_servers', [])
        
        return render_template('jenkins_servers.html', jenkins_servers=jenkins_servers)
    
    @app.route('/admin/add-jenkins-server', methods=['POST'])
    @admin_required
    def add_jenkins_server():
        """Add a new Jenkins server configuration"""
        settings = load_settings()
        
        if 'jenkins_servers' not in settings:
            settings['jenkins_servers'] = []
        
        # Generate a unique ID for the server
        server_id = str(uuid.uuid4())
        
        # Create a new server configuration
        new_server = {
            'id': server_id,
            'name': request.form.get('server_name', ''),
            'base_url': request.form.get('server_url', ''),
            'username': request.form.get('server_username', ''),
            'api_token': request.form.get('server_token', ''),
            'ssl_verify': 'server_ssl_verify' in request.form,
            'enabled': 'server_enabled' in request.form,
            'auto_fetch_logs': 'server_auto_fetch' in request.form,
            'poll_interval': int(request.form.get('server_poll_interval', 15)),
            'import_builds': {
                'limit': int(request.form.get('server_import_limit', 50)),
                'days': int(request.form.get('server_import_days', 30)),
                'include_successful': 'server_import_successful' in request.form
            }
        }
        
        # Add the new server to the list
        settings['jenkins_servers'].append(new_server)
        
        # Save the settings
        if save_settings(settings):
            flash(f"Jenkins server '{new_server['name']}' added successfully", 'success')
        else:
            flash("Failed to save Jenkins server configuration", 'danger')
            
        return redirect(url_for('jenkins_servers'))
    
    @app.route('/admin/update-jenkins-server', methods=['POST'])
    @admin_required
    def update_jenkins_server():
        """Update an existing Jenkins server configuration"""
        settings = load_settings()
        
        server_id = request.form.get('server_id')
        
        if not server_id or 'jenkins_servers' not in settings:
            flash("Invalid server ID or no servers configured", 'danger')
            return redirect(url_for('jenkins_servers'))
        
        # Find the server in the list
        for server in settings['jenkins_servers']:
            if server['id'] == server_id:
                # Update server configuration
                server['name'] = request.form.get('server_name', server['name'])
                server['base_url'] = request.form.get('server_url', server['base_url'])
                server['username'] = request.form.get('server_username', server['username'])
                
                # Only update API token if provided (otherwise keep existing)
                new_token = request.form.get('server_token', '')
                if new_token:
                    server['api_token'] = new_token
                
                server['ssl_verify'] = 'server_ssl_verify' in request.form
                server['enabled'] = 'server_enabled' in request.form
                server['auto_fetch_logs'] = 'server_auto_fetch' in request.form
                server['poll_interval'] = int(request.form.get('server_poll_interval', server['poll_interval']))
                
                server['import_builds'] = {
                    'limit': int(request.form.get('server_import_limit', server['import_builds']['limit'])),
                    'days': int(request.form.get('server_import_days', server['import_builds']['days'])),
                    'include_successful': 'server_import_successful' in request.form
                }
                
                # Save the settings
                if save_settings(settings):
                    flash(f"Jenkins server '{server['name']}' updated successfully", 'success')
                else:
                    flash("Failed to save Jenkins server configuration", 'danger')
                
                return redirect(url_for('jenkins_servers'))
        
        flash("Server not found", 'danger')
        return redirect(url_for('jenkins_servers'))
    
    @app.route('/admin/delete-jenkins-server', methods=['POST'])
    @admin_required
    def delete_jenkins_server():
        """Delete a Jenkins server configuration"""
        settings = load_settings()
        
        server_id = request.form.get('server_id')
        
        if not server_id or 'jenkins_servers' not in settings:
            flash("Invalid server ID or no servers configured", 'danger')
            return redirect(url_for('jenkins_servers'))
        
        # Find the server in the list
        for i, server in enumerate(settings['jenkins_servers']):
            if server['id'] == server_id:
                # Remove the server
                deleted_server = settings['jenkins_servers'].pop(i)
                
                # Save the settings
                if save_settings(settings):
                    flash(f"Jenkins server '{deleted_server['name']}' deleted successfully", 'success')
                else:
                    flash("Failed to delete Jenkins server configuration", 'danger')
                
                return redirect(url_for('jenkins_servers'))
        
        flash("Server not found", 'danger')
        return redirect(url_for('jenkins_servers'))
    
    @app.route('/admin/test-jenkins-server-connection', methods=['POST'])
    @admin_required
    def test_jenkins_server_connection():
        """Test connection to a Jenkins server"""
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'Invalid request data'})
        
        url = data.get('url', '')
        username = data.get('username', '')
        api_token = data.get('api_token', '')
        verify_ssl = data.get('verify_ssl', True)
        
        if not url:
            return jsonify({'success': False, 'error': 'Jenkins URL is required'})
        
        # Ensure URL ends with a slash
        if not url.endswith('/'):
            url += '/'
        
        try:
            # Try to connect to Jenkins API
            api_url = f"{url}api/json"
            auth = None
            
            if username and api_token:
                auth = (username, api_token)
            
            response = requests.get(api_url, auth=auth, verify=verify_ssl, timeout=10)
            
            if response.status_code == 200:
                jenkins_data = response.json()
                
                # Get Jenkins version from headers
                version = response.headers.get('X-Jenkins', 'Unknown')
                
                # Count jobs
                jobs_count = len(jenkins_data.get('jobs', []))
                
                return jsonify({
                    'success': True,
                    'version': version,
                    'jobs_count': jobs_count
                })
            else:
                return jsonify({
                    'success': False,
                    'error': f"HTTP Error: {response.status_code} - {response.reason}"
                })
                
        except requests.exceptions.SSLError:
            return jsonify({
                'success': False,
                'error': 'SSL certificate verification failed. Try enabling "Verify SSL certificates".'
            })
        except requests.exceptions.ConnectionError:
            return jsonify({
                'success': False,
                'error': 'Could not connect to Jenkins server. Please check the URL and network connection.'
            })
        except requests.exceptions.Timeout:
            return jsonify({
                'success': False,
                'error': 'Connection timed out. The Jenkins server may be down or unreachable.'
            })
        except requests.exceptions.RequestException as e:
            return jsonify({
                'success': False,
                'error': f"Request error: {str(e)}"
            })
        except ValueError as e:
            return jsonify({
                'success': False,
                'error': f"Invalid response from Jenkins (not valid JSON): {str(e)}"
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f"Unexpected error: {str(e)}"
            })