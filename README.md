# 🚀 StartupApp
- StartupApp is a Flask-based web application that allows users to register, submit startup ideas, and vote on others. It features user authentication, image uploads, a voting system, and basic search functionality — built using Flask, SQLAlchemy, WTForms, and Bootstrap.

# 🌟 Features
- 🔐 User Authentication with Flask-Login
- ✍️ Submit, Edit, and View Startup Ideas
- 👍 Voting System (1 vote per user per startup)
- 🖼️ Image Upload Support
- 🔍 Search Startups
- 🧃 Flash Messages using Bootstrap Alerts
- ⏱️ Rate Limiting with Flask-Limiter
- 🔐 Secure Password Hashing (PBKDF2)
- 🧼 Security: WTForms validation, file sanitization, and input escaping

# 🛠️ Tech Stack
- Backend: Python, Flask, SQLAlchemy, Flask-Login, Flask-WTF
- Frontend: HTML, Bootstrap, Jinja2
- Database: SQLite
- Security: WTForms, Flask-Limiter, secure file uploads

# 🚀 Getting Started
1. Clone the Repository
- git clone https://github.com/pioneershahid/StartupApp.git
- cd StartupApp

2. Install Dependencies 
- pip install -r requirements.txt

3. Configure Environment Variables
Create a .env file in the root directory with the following:
- SECRET_KEY=your_secret_key 
- SQLALCHEMY_DATABASE_URI=sqlite:///startups.db 
- UPLOAD_FOLDER=static/uploads

4. Run the App
- python app.py 
- Visit http://127.0.0.1:5000

# 🔐 Test Accounts
You can use the following sample accounts to explore the app:
- Emails: shahid@example.com, john@example.com, jane@example.com
- Password: example
Or simply create a new account through the registration page.

# 🧠 To-Do / Future Enhancements
- Pagination for startups
- Admin dashboard for analytics
- Email confirmation for new User
- push the repository on Github for track changes
- Custom domain for production site
- CI/CD pipeline (GitHub Actions/Terraform)
- Deploy to cloud (AWS, Azure)