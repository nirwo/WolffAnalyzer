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
