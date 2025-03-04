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
                # Make a safe copy of logs with critical_issues as a number
                processed_logs = []
                for log in user_data['logs']:
                    processed_log = dict(log)  # Make a copy
                    # Ensure critical_issues is a number
                    if 'critical_issues' in processed_log:
                        try:
                            if hasattr(processed_log['critical_issues'], 'read'):  # Check if it's a file-like object
                                processed_log['critical_issues'] = 0
                            else:
                                processed_log['critical_issues'] = int(processed_log['critical_issues'])
                        except (TypeError, ValueError):
                            processed_log['critical_issues'] = 0
                    else:
                        processed_log['critical_issues'] = 0
                    processed_logs.append(processed_log)
                processed_user['logs'] = processed_logs
            
            users_list.append(processed_user)
                
        return render_template('admin_users.html', users=users_list, user=current_user)
    except Exception as e:
        logger.error(f'Error in admin_users: {str(e)}')
        flash(f'Error loading users: {str(e)}')
        return redirect(url_for('index'))
