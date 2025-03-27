# Gossip Girl Blog

A Gossip Girl-themed blogging platform where users can register, login, and admin users can post gossip. Built with Node.js, Express, and EJS.

## Features

- User authentication (register/login)
- Admin users can create blog posts
- Gossip Girl themed UI
- JSON-based data storage
- Secure password hashing
- JWT-based authentication

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file in the root directory with the following variables:
```
# Server Configuration
PORT=2000
JWT_SECRET=your_jwt_secret_here
ACCESS_PIN=your_access_pin_here

# Email Configuration
EMAIL_SYSTEM_ENABLED=true
EMAIL_PROVIDER=resend  # Options: resend, sendgrid, mailgun, smtp
EMAIL_FROM=your_sender_email@example.com

# SendGrid Configuration (if using SendGrid)
SENDGRID_API_KEY=your_sendgrid_api_key_here

# Mailgun Configuration (if using Mailgun)
MAILGUN_API_KEY=your_mailgun_api_key_here
MAILGUN_DOMAIN=your_mailgun_domain_here

# Resend Configuration (if using Resend)
RESEND_API_KEY=your_resend_api_key_here

# SMTP Configuration (legacy, used as fallback)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_SECURE=false
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_specific_password

# Site Configuration
SITE_URL=your_site_url_here
```

3. Start the server:
```bash
npm start
```

For development with auto-reload:
```bash
npm run dev
```

## Usage

1. Register a new account at `/register`
2. Login with your credentials at `/login`
3. Admin users can create new posts at `/create-post`
4. View all posts on the home page

## File Structure

- `server.js` - Main application file
- `views/` - EJS templates
  - `layout.ejs` - Main layout template
  - `index.ejs` - Home page
  - `login.ejs` - Login page
  - `register.ejs` - Registration page
  - `create-post.ejs` - Post creation page
- `data/` - JSON data storage
  - `users.json` - User data
  - `posts.json` - Blog posts

## Making a User an Admin

To make a user an admin, manually edit their record in `data/users.json` and set `isAdmin: true`.

XOXO, Gossip Girl