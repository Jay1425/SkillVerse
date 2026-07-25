# 🚀 SkillVerse – Skill Swap Platform

> **SkillVerse** is a full-stack web application developed during the **Odoo Hackathon**. It is a community-driven platform that enables users to exchange skills instead of paying for courses. Users can teach the skills they know while learning new skills from others, creating a collaborative learning ecosystem.

---

## 📌 Problem Statement

Many people possess valuable skills but cannot afford expensive learning platforms. At the same time, many skilled individuals are willing to teach but lack a platform to connect with learners.

**SkillVerse** bridges this gap by allowing users to exchange knowledge through mutual learning, making education more accessible and collaborative.

---

# ✨ Features

- 🔐 Secure User Authentication
- 👤 User Profile Management
- 🛠️ Add and Manage Skills
- 🔍 Browse Available Skills
- 🤝 Create Skill Swap Requests
- ✅ Accept or Reject Requests
- 📊 Dashboard for Users
- ⚙️ User Settings & Privacy Controls
- 🔒 Password Encryption
- 📱 Responsive User Interface

---

# 🛠️ Tech Stack

## Frontend

- HTML5
- CSS3
- Tailwind CSS
- JavaScript
- Jinja2 Templates

## Backend

- Python
- Flask

## Database

- SQLite
- SQLAlchemy ORM

## Authentication

- Flask-Login
- Werkzeug Password Hashing

---

# 🏗️ System Architecture

```
                User
                  │
                  ▼
        HTML + Tailwind CSS
                  │
                  ▼
            Flask Routes
                  │
      ┌───────────┴───────────┐
      │                       │
 Authentication        Business Logic
      │                       │
      └───────────┬───────────┘
                  │
          SQLAlchemy ORM
                  │
                  ▼
           SQLite Database
```

---

# 📂 Project Structure

```
SkillVerse
│
├── app.py
├── requirements.txt
├── README.md
│
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── signup.html
│   ├── dashboard.html
│   ├── browse.html
│   ├── profile.html
│   ├── add_skill.html
│   ├── request_swap.html
│   ├── my_swaps.html
│   └── admin.html
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
└── database/
```

---

# 🗄️ Database Design

The application uses three main entities.

## 1. User

Stores user information.

### Fields

- User ID
- Username
- Email
- Password (Hashed)
- Bio
- Location
- Profile Visibility
- Notification Preferences
- Created Date

---

## 2. Skill

Stores the skills uploaded by users.

### Fields

- Skill ID
- Skill Name
- Description
- Category
- Difficulty Level
- User ID
- Created Date
- Status

---

## 3. Swap Request

Stores requests exchanged between users.

### Fields

- Request ID
- Offered Skill
- Requested Skill
- Requester ID
- Receiver ID
- Status
- Description
- Created Date

### Status

- Open
- Accepted
- Completed
- Cancelled

---

# 🔄 Application Workflow

## Step 1 – User Registration

```
User
   │
Signup Form
   │
Validation
   │
Password Hashing
   │
Store in Database
   │
Login Page
```

### Description

A new user registers by providing their username, email, and password. The password is securely hashed before being stored in the database.

---

## Step 2 – User Login

```
User Login
      │
Validate Credentials
      │
Check Password Hash
      │
Create Session
      │
Dashboard
```

### Description

The system authenticates users using Flask-Login. After successful authentication, a secure session is created, allowing access to protected pages.

---

## Step 3 – Dashboard

After login, users are redirected to their dashboard where they can:

- View Profile
- View Skills
- View Swap Requests
- Manage Account
- Navigate Throughout the Platform

---

## Step 4 – Add Skills

```
User
   │
Skill Form
   │
Validation
   │
Save Skill
   │
Database
```

### Description

Users can upload the skills they are willing to teach by providing:

- Skill Name
- Description
- Category
- Difficulty Level

Each skill is associated with the respective user.

---

## Step 5 – Browse Skills

```
Database
     │
Retrieve Skills
     │
Display Skill Cards
```

Users can browse all publicly available skills and find people willing to teach them.

Each skill card displays:

- Skill Name
- Description
- Category
- Difficulty
- Owner

---

## Step 6 – Skill Swap Request

Example:

User A knows Python.

User B knows Photoshop.

User A wants to learn Photoshop.

```
User A
     │
Select Skill
     │
Create Request
     │
Database
     │
User B Receives Request
```

The request contains:

- Offered Skill
- Requested Skill
- Request Description
- Status

---

## Step 7 – Request Management

The receiver can

- Accept Request
- Reject Request
- Mark as Completed

The request status is automatically updated in the database.

---

## Step 8 – Profile Management

Users can update

- Bio
- Location
- Profile Visibility
- Email Preferences

---

## Step 9 – Settings

The application provides user settings for

- Public Profile
- Notifications
- Privacy
- Account Preferences

---

# 🔐 Authentication Flow

```
Login
   │
User Exists?
   │
Password Correct?
   │
Create Session
   │
Protected Pages
   │
Logout
```

Protected pages are accessible only to authenticated users using Flask-Login.

---

# 🔄 Skill Swap Flow

```
User Registers
       │
Creates Profile
       │
Adds Skills
       │
Browses Skills
       │
Finds Another User
       │
Creates Swap Request
       │
Receiver Accepts
       │
Knowledge Exchange
       │
Request Completed
```

---

# 🔗 Database Relationships

```
User
 │
 ├────────► Skills
 │
 └────────► Swap Requests
```

- One User can own multiple Skills.
- One User can send multiple Swap Requests.
- One User can receive multiple Swap Requests.
- Each Skill belongs to only one User.

---

# 🔒 Security Features

### Password Hashing

Passwords are never stored as plain text.

```
generate_password_hash()
check_password_hash()
```

---

### Session Management

Flask-Login manages secure user sessions.

```
@login_required
```

Only authenticated users can access protected routes.

---

### Form Validation

The application validates

- Required Fields
- Email Format
- Password Length
- User Inputs

before storing data in the database.

---

# 💡 Business Logic

```
Register
    │
Login
    │
Create Profile
    │
Add Skills
    │
Browse Skills
    │
Create Swap Request
    │
Accept Request
    │
Exchange Skills
    │
Complete Request
```

---

# 🎯 Why Flask?

Flask was selected because it provides

- Lightweight architecture
- Easy routing
- Fast development
- SQLAlchemy integration
- Simple template rendering
- Perfect for hackathon projects

---

# 🗄️ Why SQLite?

SQLite was chosen because

- Lightweight
- No server setup required
- Easy integration
- Suitable for prototypes and hackathons

---

# 📚 Learning Outcomes

Through this project, we gained hands-on experience in:

- Full Stack Web Development
- Flask Framework
- SQLAlchemy ORM
- SQLite Database
- User Authentication
- Session Management
- CRUD Operations
- Database Relationships
- RESTful Application Design
- Responsive UI Development
- Team Collaboration during Hackathon
- Git & GitHub Workflow

---

# 👨‍💻 Developed During

**Odoo Hackathon**

SkillVerse was built as a hackathon project to promote collaborative learning by enabling users to exchange knowledge instead of money. The project demonstrates full-stack development concepts including authentication, database management, user interaction, and secure application design.

---

# 📄 License

This project is developed for educational and hackathon purposes.
