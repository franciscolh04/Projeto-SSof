user_data = request.GET['id']
query = "SELECT * FROM users WHERE id = " + user_data
cursor.execute(query)