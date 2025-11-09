Team Performance & Attendance Tracker\n\nSimple Flask demo app for tracking agent Time In / Time Out and admin-managed performance scores.\n\nQuick start (Windows PowerShell):\n\n1. Create a virtual environment and activate it\n
# Team Performance & Attendance Tracker

A comprehensive Flask web application for tracking team member attendance, time tracking, and performance metrics. Designed for teams of up to 25 members with clean, intuitive interfaces for both Agents and Administrators.

## Features

### Agent Features
- **Time Tracking**: Simple "Time In" and "Time Out" buttons to track work hours
- **Attendance History**: View personal attendance records with login/logout times and total hours
- **Performance Dashboard**: View CSAT, DSAT scores, and performance reviews set by Admin
- **Profile Management**: Update password and view detailed attendance statistics
- **Announcements**: View team announcements and updates from Admin

### Admin Features
- **Team Management**: View and manage all team members
- **Performance Tracking**: Update CSAT/DSAT scores (0-10 scale) and performance reviews for each agent
- **Attendance Monitoring**: View all attendance records, track active sessions, and monitor team status
- **Export Functionality**: Export attendance data to CSV or Excel format with optional date range filtering
- **Announcements System**: Post team-wide announcements with optional expiration dates
- **Dashboard Analytics**: View team performance averages, active agent count, and attendance statistics
- **Agent History**: View detailed attendance history for any team member

## Quick Start

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Installation

1. Create a virtual environment and activate it:

```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

```bash
# Linux/Mac
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Run the application:

```powershell
# Windows
python app.py
```

```bash
# Linux/Mac
python3 app.py
```

3. Open http://127.0.0.1:5000 in your browser

### Default Credentials

On first run, a default admin user is automatically created:
- **Username**: `admin`
- **Password**: `admin123`

**⚠️ Important**: Change the default admin password after first login!

### Creating New Users

When you sign in with a new name and password for the first time, the app will automatically create a new user account. Select your role (Agent or Admin) during the login process.

## Usage Guide

### For Agents

1. **Time Tracking**: Click "Time In" when starting work and "Time Out" when finishing
2. **View Performance**: Check your CSAT/DSAT scores and reviews on your dashboard
3. **Profile**: Access "My Profile" to view detailed attendance history and change password
4. **Announcements**: Check the announcements page for team updates

### For Administrators

1. **Team Overview**: View all team members and their current status on the admin dashboard
2. **Manage Performance**: Click the edit icon next to any agent to update CSAT/DSAT scores and reviews
3. **Export Data**: Use the "Export Data" dropdown to export attendance reports (CSV or Excel format)
4. **Date Filtering**: When exporting, optionally specify date ranges for filtered reports
5. **Post Announcements**: Create team-wide announcements with optional expiration dates
6. **Monitor Activity**: See which agents are currently logged in and view recent attendance records

## Data Storage

- All data is stored in SQLite database: `instance/attendance.db`
- The database includes tables for:
  - Agents (users, roles, performance metrics)
  - Attendance records (login/logout times, hours worked)
  - Announcements (team communications)

## Technology Stack

- **Backend**: Flask (Python web framework)
- **Database**: SQLAlchemy with SQLite
- **Authentication**: Flask-Login with password hashing
- **Frontend**: Bootstrap 5, Font Awesome icons
- **Export**: CSV (built-in) and Excel (openpyxl)

## Security Notes

⚠️ **Production Deployment Warning**: This application is designed for internal team use. For production deployment:

- Change the `SECRET_KEY` in `app.py` to a strong, random value
- Enable HTTPS/SSL encryption
- Implement proper password reset functionality
- Add rate limiting and additional security measures
- Regular database backups
- Consider using PostgreSQL or MySQL for production

## Environment variables (for deployment)

When deploying (for example to Vercel) you should set the following environment variables in the deployment dashboard:

- `SECRET_KEY` or `FLASK_SECRET_KEY` — the Flask secret key used for sessions and CSRF protection. Provide a long random string in production.
- `DATABASE_URL` or `SQLALCHEMY_DATABASE_URI` — the full database connection URL. Example for PostgreSQL:
  - `postgresql://USER:PASS@HOST:PORT/DBNAME`
  - Note: if your provider gives you a URL starting with `postgres://`, the app will automatically normalize it to `postgresql://`.
- `FLASK_DEBUG` — optional (`0` or `1`) to toggle debug mode (use `0` in production).

If no `DATABASE_URL` or `SQLALCHEMY_DATABASE_URI` is provided the app falls back to a local SQLite file at `instance/attendance.db` (suitable for local development only — not persistent on ephemeral hosts).

Setting environment variables in Vercel:

1. Go to your project in the Vercel dashboard.
2. Open the "Settings" → "Environment Variables" section.
3. Add the variables above for the appropriate environment (Preview/Production).
4. Redeploy your project after saving the variables.

Example minimal variables for production on Vercel:

```
SECRET_KEY=some-long-random-string
DATABASE_URL=postgresql://username:password@db-host.example.com:5432/emp_mngmt
FLASK_DEBUG=0
```

## Support

For issues or feature requests, please contact your system administrator.

---

**Version**: 1.0.0  
**Last Updated**: 2024