# StartupApp
Startup Showcase Platform
A Flask web application for users to register, submit their startup ideas, and vote on others. Built with Flask, SQLAlchemy, Flask-WTF, and more.

Features
- User Registration & Login (Flask-Login)
- Submit, Edit, and View Startups
- Voting System (1 vote per user per startup)
- Image Upload Support
- Search Startups
- Rate Limiting (Flask-Limiter)
- Secure Password Hashing (PBKDF2)
- Flash Messages with Bootstrap Alerts
- Backend: Python, Flask, Flask-SQLAlchemy, Flask-Login
- Frontend: HTML, Bootstrap, Jinja2
- Database: SQLite
- Security: WTForms Validation, File Upload Sanitization, Input Escaping


Getting Started
1. Unzip and open the Repository in VScode or other IDE
cd startup
Use the provided startups.db to see the full working webpage. 
Use "shahid@example.com", "john@example.com" and "jane@example.com" with password "example" OR create new User.

2. Install Dependencies
pip install -r requirements.txt

4. Environment Variables
Create a .env file in the root directory:
SECRET_KEY=your_secret_key
SQLALCHEMY_DATABASE_URI=sqlite:///startups.db
UPLOAD_FOLDER=static/uploads

5. Run the App
python app.py
Visit http://127.0.0.1:5000

Project Structure
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── submit.html
│   ├── edit_startup.html
│   └── detail_startup.html
├── static/uploads/
├── app.py
├── .env
└── requirements.txt

To-Do / Ideas
1. Pagination for large lists of startups
2. Admin dashboard for analytics
3. Email confirmation for accounts
4. push the repository on Github for track changes
5. Get dedicated Domain name and publish the website
6. Develop CI/CD pipeline for automatic deployment
7. Deploy the website on the Cloud using AWS/AZUR



