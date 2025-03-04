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
