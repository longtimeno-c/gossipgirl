const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const expressLayouts = require('express-ejs-layouts');
const nodemailer = require('nodemailer');
const sgMail = require('@sendgrid/mail');
const formData = require('form-data');
const Mailgun = require('mailgun.js');
const { Resend } = require('resend');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));
app.use(session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Set EJS as templating engine
app.use(expressLayouts);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout');

// Data storage paths
const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const POSTS_FILE = path.join(__dirname, 'data', 'posts.json');
const SUBMISSIONS_FILE = path.join(__dirname, 'data', 'submissions.json');
const INVITES_FILE = path.join(__dirname, 'data', 'invite.json');

// Ensure data directory and files exist
if (!fs.existsSync(path.join(__dirname, 'data'))) {
    fs.mkdirSync(path.join(__dirname, 'data'));
}

if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([]));
}

if (!fs.existsSync(POSTS_FILE)) {
    fs.writeFileSync(POSTS_FILE, JSON.stringify([]));
}

if (!fs.existsSync(SUBMISSIONS_FILE)) {
    fs.writeFileSync(SUBMISSIONS_FILE, JSON.stringify([]));
}

if (!fs.existsSync(INVITES_FILE)) {
    fs.writeFileSync(INVITES_FILE, JSON.stringify([]));
}

// Authentication middleware
const authenticateUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/login');
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Get fresh user data from database
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        const user = users.find(u => u.id === decoded.id);
        
        if (!user) {
            res.clearCookie('token');
            return res.redirect('/login');
        }
        
        req.user = {
            id: user.id,
            username: user.username,
            isAdmin: user.isAdmin
        };
        res.locals.user = req.user;
        next();
    } catch (err) {
        res.clearCookie('token');
        res.redirect('/login');
    }
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).render('error', { error: 'Access denied. Admin privileges required.' });
    }
    next();
};

// Add user to res.locals middleware
app.use(async (req, res, next) => {
    const token = req.cookies.token;
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            // Get fresh user data from database
            const users = JSON.parse(fs.readFileSync(USERS_FILE));
            const user = users.find(u => u.id === decoded.id);
            
            if (user) {
                // Update the user object with fresh data
                res.locals.user = {
                    id: user.id,
                    username: user.username,
                    isAdmin: user.isAdmin
                };
            } else {
                res.locals.user = null;
                res.clearCookie('token');
            }
        } catch (err) {
            res.locals.user = null;
            res.clearCookie('token');
        }
    } else {
        res.locals.user = null;
    }
    next();
});

// Email configuration
let transporter = null;
let emailProvider = null;
let mailgun = null;
let resend = null;

if (process.env.EMAIL_SYSTEM_ENABLED === 'true') {
    if (process.env.EMAIL_PROVIDER === 'sendgrid') {
        // Use SendGrid
        sgMail.setApiKey(process.env.SENDGRID_API_KEY);
        emailProvider = 'sendgrid';
        console.log('SendGrid email provider configured');
    } else if (process.env.EMAIL_PROVIDER === 'mailgun') {
        // Use Mailgun
        const mailgunClient = new Mailgun(formData);
        mailgun = mailgunClient.client({
            username: 'api',
            key: process.env.MAILGUN_API_KEY,
        });
        emailProvider = 'mailgun';
        console.log('Mailgun email provider configured');
    } else if (process.env.EMAIL_PROVIDER === 'resend') {
        // Use Resend
        resend = new Resend(process.env.RESEND_API_KEY);
        emailProvider = 'resend';
        console.log('Resend email provider configured');
    } else {
        // Fallback to SMTP
        transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.EMAIL_PORT || '587'),
            secure: process.env.EMAIL_SECURE === 'true',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            }
        });

        // Verify email configuration on startup
        transporter.verify((error, success) => {
            if (error) {
                console.log('SMTP connection error:', error);
                console.log('Environment details:');
                console.log('- Node version:', process.version);
                console.log('- Platform:', process.platform);
                console.log('- SMTP Config:', {
                    host: process.env.EMAIL_HOST,
                    port: process.env.EMAIL_PORT,
                    secure: process.env.EMAIL_SECURE,
                    user: !!process.env.EMAIL_USER,
                    pass: !!process.env.EMAIL_PASS
                });
            } else {
                console.log('SMTP server is ready to take our messages');
            }
        });
        emailProvider = 'smtp';
    }
} else {
    console.log('Email system is disabled');
}

// Store reset codes temporarily (in production, use a database)
const resetCodes = new Map();

// Generate a random 6-digit code
function generateResetCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Check if email system is enabled
function isEmailSystemEnabled() {
    return process.env.EMAIL_SYSTEM_ENABLED === 'true';
}

// Send email function that abstracts provider details
async function sendEmail(options) {
    if (!isEmailSystemEnabled()) {
        throw new Error('Email system is disabled');
    }

    if (emailProvider === 'sendgrid') {
        const msg = {
            to: options.to,
            from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
            subject: options.subject,
            html: options.html,
        };
        return sgMail.send(msg);
    } else if (emailProvider === 'mailgun') {
        const mailgunOptions = {
            from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
            to: options.to,
            subject: options.subject,
            html: options.html
        };
        return mailgun.messages.create(process.env.MAILGUN_DOMAIN, mailgunOptions);
    } else if (emailProvider === 'resend') {
        return resend.emails.send({
            from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
            to: options.to,
            subject: options.subject,
            html: options.html
        });
    } else if (emailProvider === 'smtp') {
        return transporter.sendMail(options);
    } else {
        throw new Error('No email provider configured');
    }
}

// Add to public routes
const publicRoutes = [
    '/login',
    '/register',
    '/favicon.ico',
    '/css',
    '/js',
    '/images',
    '/forgot-password',
    '/verify-code',
    '/verify-email',
    '/reset-password'
];

// Middleware to check if the route is public
const requireAuth = (req, res, next) => {
    if (publicRoutes.some(route => req.path.startsWith(route))) {
        return next();
    }
    return authenticateUser(req, res, next);
};

// Apply authentication middleware to all routes except public ones
app.use(requireAuth);

// Routes
app.get('/', (req, res) => {
    const posts = JSON.parse(fs.readFileSync(POSTS_FILE));
    const successMessage = req.query.accountCreated ? 'Your account was created successfully!' : null;
    res.render('index', { 
        posts: posts.sort((a, b) => b.timestamp - a.timestamp),
        successMessage
    });
});

// Profile routes
app.get('/profile/:userId', (req, res) => {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const posts = JSON.parse(fs.readFileSync(POSTS_FILE));
    const submissions = JSON.parse(fs.readFileSync(SUBMISSIONS_FILE));
    
    const profileUser = users.find(u => u.id === req.params.userId);
    if (!profileUser) {
        return res.status(404).render('error', { error: 'User not found' });
    }

    // Get posts authored by this user and posts created from their submissions
    const userPosts = posts.filter(post => post.author === profileUser.username)
        .sort((a, b) => b.timestamp - a.timestamp);
        
    // Get pending submissions by this user
    const userSubmissions = submissions.filter(submission => submission.submitter === profileUser.username)
        .sort((a, b) => b.timestamp - a.timestamp);

    res.render('profile', { profileUser, userPosts, userSubmissions });
});

app.post('/update-profile', async (req, res) => {
    try {
        const { email, newPassword } = req.body;
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        const userIndex = users.findIndex(u => u.id === req.user.id);

        if (userIndex === -1) {
            return res.json({ success: false, message: 'User not found' });
        }

        users[userIndex].email = email;
        
        if (newPassword) {
            users[userIndex].password = await bcrypt.hash(newPassword, 10);
        }

        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Story submission routes
app.get('/submit-story', authenticateUser, (req, res) => {
    if (req.user.isAdmin) {
        return res.redirect('/create-post');
    }
    res.render('submit-story', { error: null, success: null });
});

app.post('/submit-story', authenticateUser, (req, res) => {
    if (req.user.isAdmin) {
        return res.status(403).render('error', { error: 'Admins should use the create post page' });
    }

    try {
        const { title, content } = req.body;
        const submissions = JSON.parse(fs.readFileSync(SUBMISSIONS_FILE));
        
        const newSubmission = {
            id: Date.now().toString(),
            title,
            content,
            submitter: req.user.username,
            timestamp: Date.now()
        };

        submissions.push(newSubmission);
        fs.writeFileSync(SUBMISSIONS_FILE, JSON.stringify(submissions, null, 2));
        res.render('submit-story', { success: 'Your story has been submitted for review!', error: null });
    } catch (error) {
        res.render('submit-story', { error: 'Failed to submit story. Please try again.', success: null });
    }
});

// Admin routes
app.get('/admin', requireAdmin, (req, res) => {
    const users = JSON.parse(fs.readFileSync(USERS_FILE));
    const posts = JSON.parse(fs.readFileSync(POSTS_FILE));
    const submissions = JSON.parse(fs.readFileSync(SUBMISSIONS_FILE));
    const invites = JSON.parse(fs.readFileSync(INVITES_FILE));
    
    res.render('admin-dashboard', { 
        users: users.map(u => ({ ...u, password: undefined })),
        posts: posts.sort((a, b) => b.timestamp - a.timestamp),
        submissions: submissions.sort((a, b) => b.timestamp - a.timestamp),
        invites
    });
});

app.put('/admin/posts/:postId', requireAdmin, (req, res) => {
    try {
        const { title, content, reactions } = req.body;
        const posts = JSON.parse(fs.readFileSync(POSTS_FILE));
        const postIndex = posts.findIndex(p => p.id === req.params.postId);

        if (postIndex === -1) {
            return res.json({ success: false, message: 'Post not found' });
        }

        // Get existing reactions or initialize new ones
        const existingReactions = posts[postIndex].reactions || {};

        // Handle reaction counts from admin
        if (reactions) {
            // For each reaction type, create an array of fake user IDs based on the count
            Object.keys(reactions).forEach(type => {
                const count = reactions[type];
                if (count > 0) {
                    // Create an array of specified length with fake user IDs
                    // Format: 'admin-set-1', 'admin-set-2', etc.
                    existingReactions[type] = Array.from({ length: count }, (_, i) => `admin-set-${i + 1}`);
                } else {
                    // If count is 0, set empty array
                    existingReactions[type] = [];
                }
            });
        }

        posts[postIndex] = {
            ...posts[postIndex],
            title,
            content,
            reactions: existingReactions,
            editedAt: Date.now()
        };

        fs.writeFileSync(POSTS_FILE, JSON.stringify(posts, null, 2));
        res.json({ success: true, title, reactions: existingReactions });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

app.delete('/admin/posts/:postId', requireAdmin, (req, res) => {
    try {
        const posts = JSON.parse(fs.readFileSync(POSTS_FILE));
        const filteredPosts = posts.filter(p => p.id !== req.params.postId);
        
        fs.writeFileSync(POSTS_FILE, JSON.stringify(filteredPosts, null, 2));
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

app.post('/admin/users/:userId/toggle-admin', requireAdmin, (req, res) => {
    try {
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        const userIndex = users.findIndex(u => u.id === req.params.userId);

        if (userIndex === -1) {
            return res.json({ success: false, message: 'User not found' });
        }

        users[userIndex].isAdmin = !users[userIndex].isAdmin;
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

app.delete('/admin/users/:userId', requireAdmin, (req, res) => {
    try {
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        const filteredUsers = users.filter(u => u.id !== req.params.userId);
        
        fs.writeFileSync(USERS_FILE, JSON.stringify(filteredUsers, null, 2));
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

app.post('/admin/submissions/:submissionId/approve', requireAdmin, (req, res) => {
    try {
        const submissions = JSON.parse(fs.readFileSync(SUBMISSIONS_FILE));
        const posts = JSON.parse(fs.readFileSync(POSTS_FILE));
        
        const submission = submissions.find(s => s.id === req.params.submissionId);
        if (!submission) {
            return res.json({ success: false, message: 'Submission not found' });
        }

        // Create new post from submission - keep original submitter as author
        const newPost = {
            id: Date.now().toString(),
            title: submission.title,
            content: submission.content,
            author: submission.submitter, // Use the submitter's name as the author
            timestamp: Date.now(),
            reactions: {
                heart: [],
                shocked: [],
                xoxo: []
            }
        };

        posts.push(newPost);
        fs.writeFileSync(POSTS_FILE, JSON.stringify(posts, null, 2));

        // Remove submission
        const filteredSubmissions = submissions.filter(s => s.id !== req.params.submissionId);
        fs.writeFileSync(SUBMISSIONS_FILE, JSON.stringify(filteredSubmissions, null, 2));

        // Send email notification to all users about the new post
        if (isEmailSystemEnabled()) {
            try {
                const users = JSON.parse(fs.readFileSync(USERS_FILE));
                
                // Send notification to each user with an email
                users.forEach(async (user) => {
                    if (user.email) {
                        const notificationOptions = {
                            from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
                            to: user.email,
                            subject: `New Taunton Girl Post: ${newPost.title}`,
                            html: `
                                <!DOCTYPE html>
                                <html lang="en">
                                <head>
                                    <meta charset="UTF-8">
                                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                    <title>New Post - Taunton Girl</title>
                                    <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&family=Cormorant+Garamond:wght@400;600&display=swap" rel="stylesheet">
                                </head>
                                <body style="margin: 0; padding: 0; font-family: 'Cormorant Garamond', serif; color: #2C1810; background-color: #F7F3E3;">
                                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                                        <div style="text-align: center; margin-bottom: 30px;">
                                            <h1 style="font-family: 'Playfair Display', serif; color: #2C5530; margin: 0; font-size: 36px; font-weight: 700;">
                                                <span style="color: #C9A227;">✧</span> Taunton Girl <span style="color: #C9A227;">✧</span>
                                            </h1>
                                            <p style="font-style: italic; color: #1B4965; margin-top: 5px; font-size: 18px;">Your exclusive source into Somerset's finest</p>
                                        </div>
                                        
                                        <div style="background-color: #ffffff; border-left: 4px solid #2C5530; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(44, 85, 48, 0.2);">
                                            <h2 style="font-family: 'Playfair Display', serif; color: #1B4965; margin-top: 0; font-size: 26px; text-align: center;">
                                                Fresh Somerset Tea Just Poured
                                            </h2>
                                            
                                            <p style="font-size: 17px; line-height: 1.6; color: #2C1810; margin-bottom: 25px; font-weight: 500;">
                                                Darling ${user.username}, 
                                            </p>
                                            
                                            <p style="font-size: 17px; line-height: 1.6; color: #2C1810; margin-bottom: 25px; font-weight: 500;">
                                                A juicy new story from the heart of Somerset has just been published, and you simply <em>must</em> read it at once!
                                            </p>
                                            
                                            <div style="text-align: center; margin: 30px 0; padding: 20px; border: 2px dashed #C9A227; background-color: #FFFDF5; box-shadow: 0 4px 10px rgba(201, 162, 39, 0.1);">
                                                <h3 style="font-family: 'Playfair Display', serif; color: #2C5530; margin: 0; font-size: 24px; font-weight: 700;">
                                                    "${newPost.title}"
                                                </h3>
                                            </div>
                                            
                                            <div style="text-align: center; margin-top: 30px;">
                                                <a href="${process.env.SITE_URL || 'http://localhost:3000'}" style="display: inline-block; font-family: 'Playfair Display', serif; background-color: #2C5530; color: #F7F3E3; text-decoration: none; padding: 12px 25px; border-radius: 4px; font-size: 17px; font-weight: 600; box-shadow: 0 4px 6px rgba(44, 85, 48, 0.2);">
                                                    Read the Full Story
                                                </a>
                                            </div>
                                        </div>
                                        
                                        <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid rgba(44, 85, 48, 0.2);">
                                            <p style="font-style: italic; color: #C9A227; font-size: 20px; margin: 0; text-shadow: 0.5px 0.5px 1px rgba(0,0,0,0.1);">
                                                Kisses from the West Country,
                                            </p>
                                            <p style="font-family: 'Playfair Display', serif; color: #2C5530; font-size: 24px; margin: 5px 0 0 0; font-weight: 700;">
                                                Taunton Girl
                                            </p>
                                            <p style="font-family: 'Cormorant Garamond', serif; color: #1B4965; font-size: 16px; margin: 20px 0 0 0; font-weight: 500;">
                                                <em>Remember, in Somerset, every tale finds its way to Taunton Girl</em>
                                            </p>
                                            <p style="font-size: 13px; color: #555; margin-top: 20px; font-weight: 500;">
                                                To unsubscribe from these notifications, please update your profile settings.
                                            </p>
                                        </div>
                                    </div>
                                </body>
                                </html>
                            `
                        };
                        
                        try {
                            await sendEmail(notificationOptions);
                            console.log(`Notification email sent to ${user.email}`);
                        } catch (emailError) {
                            console.error(`Failed to send notification to ${user.email}:`, emailError);
                        }
                    }
                });
                
            } catch (emailError) {
                console.error('Error sending notification emails:', emailError);
                // Continue with the response even if emails fail
            }
        }

        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

app.post('/admin/submissions/:submissionId/reject', requireAdmin, (req, res) => {
    try {
        const submissions = JSON.parse(fs.readFileSync(SUBMISSIONS_FILE));
        const filteredSubmissions = submissions.filter(s => s.id !== req.params.submissionId);
        
        fs.writeFileSync(SUBMISSIONS_FILE, JSON.stringify(filteredSubmissions, null, 2));
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

// Existing routes
app.get('/login', (req, res) => {
    if (res.locals.user) {
        return res.redirect('/');
    }
    res.render('login', { error: null });
});

// New route for refer-friend
app.get('/refer-friend', authenticateUser, (req, res) => {
    // Only non-admin users should access this page
    if (req.user.isAdmin) {
        return res.redirect('/');
    }
    res.render('refer-friend');
});

// Handle friend referral submissions
app.post('/refer-friend', authenticateUser, (req, res) => {
    try {
        // Only non-admin users should be able to refer friends
        if (req.user.isAdmin) {
            return res.status(403).json({ success: false, message: 'Admins cannot refer friends' });
        }

        const { email } = req.body;
        
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!email || !emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: 'Please provide a valid email address' });
        }
        
        // Read existing invites
        const invites = JSON.parse(fs.readFileSync(INVITES_FILE));
        
        // Check if email already exists in invites
        if (invites.some(invite => invite.email === email)) {
            return res.status(400).json({ success: false, message: 'This email has already been invited' });
        }
        
        // Add new invite
        const newInvite = {
            id: Date.now().toString(),
            email: email,
            addedBy: req.user.username,
            addedAt: Date.now()
        };
        
        invites.push(newInvite);
        fs.writeFileSync(INVITES_FILE, JSON.stringify(invites, null, 2));
        
        return res.json({ success: true, message: 'Friend successfully invited!' });
    } catch (error) {
        console.error('Error in refer-friend:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Store registration verification codes temporarily (in production, use a database)
const registrationCodes = new Map();

app.get('/register', (req, res) => {
    if (res.locals.user) {
        return res.redirect('/');
    }
    res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
    try {
        const { username, password, email, accessPin } = req.body;
        console.log('Registration attempt:', { username, email, passwordProvided: !!password });
        
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        
        // Validate access pin
        if (!accessPin || accessPin !== process.env.ACCESS_PIN) {
            return res.render('register', { error: 'Invalid access pin. Please contact an administrator for the correct pin.' });
        }

        if (users.find(u => u.username === username)) {
            return res.render('register', { error: 'Username already exists' });
        }

        // Check if email is already in use
        if (users.find(u => u.email === email)) {
            return res.render('register', { error: 'Email address already in use' });
        }

        // Generate verification code
        const verificationCode = generateResetCode();
        console.log('Generated verification code:', verificationCode, 'for email:', email);
        
        // Store registration data temporarily
        registrationCodes.set(email, {
            code: verificationCode,
            timestamp: Date.now(),
            userData: {
                username,
                password,
                email
            }
        });
        
        console.log('Registration data stored for email:', email);
        console.log('Registration data in memory:', JSON.stringify({
            code: verificationCode,
            timestamp: 'timestamp',
            userData: {
                username,
                passwordStored: !!password,
                email
            }
        }));
        
        // Send verification email if email system is enabled
        if (isEmailSystemEnabled()) {
            try {
                const mailOptions = {
                    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
                    to: email,
                    subject: 'Verify Your Email - Taunton Girl XOXO',
                    html: `
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Email Verification - Taunton Girl</title>
                            <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&family=Cormorant+Garamond:wght@400;600&display=swap" rel="stylesheet">
                        </head>
                        <body style="margin: 0; padding: 0; font-family: 'Cormorant Garamond', serif; color: #2C1810; background-color: #F7F3E3;">
                            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                                <div style="text-align: center; margin-bottom: 30px;">
                                    <h1 style="font-family: 'Playfair Display', serif; color: #2C5530; margin: 0; font-size: 36px; font-weight: 700;">
                                        <span style="color: #C9A227;">✧</span> Taunton Girl <span style="color: #C9A227;">✧</span>
                                    </h1>
                                    <p style="font-style: italic; color: #1B4965; margin-top: 5px; font-size: 18px;">Your exclusive source into Somerset's finest</p>
                                </div>
                                
                                <div style="background-color: #ffffff; border-left: 4px solid #2C5530; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(44, 85, 48, 0.2);">
                                    <h2 style="font-family: 'Playfair Display', serif; color: #1B4965; margin-top: 0; font-size: 26px; text-align: center;">
                                        Verify Your Email
                                    </h2>
                                    
                                    <p style="font-size: 17px; line-height: 1.6; color: #2C1810; margin-bottom: 25px; font-weight: 500;">
                                        Welcome, ${username}! 
                                    </p>
                                    
                                    <p style="font-size: 17px; line-height: 1.6; color: #2C1810; margin-bottom: 25px; font-weight: 500;">
                                        Before you can access all the delicious secrets of Somerset society, we need to verify that this email belongs to you. 
                                    </p>
                                    
                                    <div style="text-align: center; margin: 30px 0;">
                                        <div style="background: linear-gradient(to right, #2C5530, #1B4965); padding: 3px; border-radius: 8px; box-shadow: 0 4px 10px rgba(44, 85, 48, 0.3);">
                                            <div style="background-color: #F7F3E3; padding: 20px; border-radius: 6px;">
                                                <h1 style="font-family: 'Playfair Display', serif; color: #C9A227; font-size: 32px; letter-spacing: 10px; margin: 0; font-weight: 700; text-shadow: 1px 1px 1px rgba(0,0,0,0.1);">
                                                    ${verificationCode}
                                                </h1>
                                            </div>
                                        </div>
                                        <p style="font-size: 15px; color: #1B4965; margin-top: 12px; font-style: italic; font-weight: 500;">
                                            This code will expire in 15 minutes, darling. Don't keep us waiting!
                                        </p>
                                    </div>
                                    
                                    <p style="font-size: 17px; line-height: 1.6; color: #2C1810; font-weight: 500;">
                                        If you didn't create an account with Taunton Girl, you can simply ignore this email.
                                    </p>
                                </div>
                                
                                <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid rgba(44, 85, 48, 0.2);">
                                    <p style="font-style: italic; color: #C9A227; font-size: 20px; margin: 0; text-shadow: 0.5px 0.5px 1px rgba(0,0,0,0.1);">
                                        Kisses from the West Country,
                                    </p>
                                    <p style="font-family: 'Playfair Display', serif; color: #2C5530; font-size: 24px; margin: 5px 0 0 0; font-weight: 700;">
                                        Taunton Girl
                                    </p>
                                    <p style="font-family: 'Cormorant Garamond', serif; color: #1B4965; font-size: 16px; margin: 20px 0 0 0; font-weight: 500;">
                                        <em>Remember, in Somerset, every tale finds its way to Taunton Girl</em>
                                    </p>
                                </div>
                            </div>
                        </body>
                        </html>
                    `
                };

                await sendEmail(mailOptions);
                res.render('verify-email', { error: null, email });
            } catch (emailError) {
                console.error('Error sending verification email:', emailError);
                res.render('register', { error: 'Failed to send verification email. Please try again.' });
            }
        } else {
            res.render('register', { error: 'Email verification is currently disabled. Please contact the administrator.' });
        }
    } catch (error) {
        res.render('register', { error: 'Registration failed. Please try again.' });
    }
});

// New route for email verification during registration
app.get('/verify-email', (req, res) => {
    const { email } = req.query;
    if (!email) {
        return res.redirect('/register');
    }
    res.render('verify-email', { error: null, email });
});

app.post('/verify-email', async (req, res) => {
    try {
        const { email, code } = req.body;
        console.log('Verifying email with code:', code, 'for email:', email);
        
        const registrationData = registrationCodes.get(email);
        console.log('Registration data found:', !!registrationData);
        
        if (registrationData) {
            console.log('Code match:', registrationData.code === code);
            console.log('Stored user data:', JSON.stringify(registrationData.userData));
        }

        if (!registrationData || registrationData.code !== code) {
            return res.render('verify-email', { 
                error: 'Invalid or expired code. Please try again.',
                email 
            });
        }

        // Check if code is expired (15 minutes)
        if (Date.now() - registrationData.timestamp > 15 * 60 * 1000) {
            registrationCodes.delete(email);
            return res.render('verify-email', { 
                error: 'Code has expired. Please register again.',
                email 
            });
        }

        // Create user account
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        const userData = registrationData.userData;
        console.log('Creating user with data:', JSON.stringify(userData));
        
        // Check if username already exists (might have been registered while verifying)
        if (users.find(u => u.username === userData.username)) {
            return res.render('verify-email', { 
                error: 'Username already exists. Please register with a different username.',
                email 
            });
        }

        // Check if email is already in use
        if (users.find(u => u.email === userData.email)) {
            return res.render('verify-email', { 
                error: 'Email address already in use. Please register with a different email.',
                email 
            });
        }
        
        // Hash the password
        console.log('Password before hashing:', typeof userData.password, userData.password ? 'exists' : 'missing');
        const hashedPassword = await bcrypt.hash(userData.password, 10);
        console.log('Password hashed successfully');
        
        const newUser = {
            id: Date.now().toString(),
            username: userData.username,
            email: userData.email,
            password: hashedPassword,
            isAdmin: false
        };
        console.log('New user object created:', newUser.username);

        // Add the new user to the database
        users.push(newUser);
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        console.log('User saved to database');
        
        // Clean up the stored verification data
        registrationCodes.delete(email);
        
        // Log the user in using the same method as the login route
        const token = jwt.sign(
            { id: newUser.id, username: newUser.username, isAdmin: newUser.isAdmin },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        console.log('JWT token created');

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        console.log('Token set in cookie');

        // Add the user to req.user and res.locals for immediate access
        req.user = {
            id: newUser.id,
            username: newUser.username,
            isAdmin: newUser.isAdmin
        };
        res.locals.user = req.user;
        console.log('User added to request and locals');

        // Redirect to homepage with a success message
        console.log('Redirecting to homepage with success message');
        res.redirect('/?accountCreated=true');
    } catch (error) {
        console.error('Error verifying email:', error);
        res.render('verify-email', { 
            error: 'Failed to verify email. Please try again.',
            email: req.body.email 
        });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        
        // Find user by username or email
        const user = users.find(u => u.username === username || u.email === username);

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.render('login', { error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, isAdmin: user.isAdmin },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        res.redirect('/');
    } catch (error) {
        res.render('login', { error: 'Login failed. Please try again.' });
    }
});

app.get('/create-post', (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).render('error', { error: 'Only admins can create posts' });
    }
    res.render('create-post', { error: null, success: null });
});

app.post('/create-post', (req, res) => {
    try {
        if (!req.user.isAdmin) {
            return res.status(403).render('error', { error: 'Only admins can create posts' });
        }

        const { title, content } = req.body;
        const posts = JSON.parse(fs.readFileSync(POSTS_FILE));
        
        // Clean up the content: trim each line while preserving intentional line breaks
        const cleanContent = content
            .split(/\r?\n/)
            .map(line => line.trim())
            .join('\n');
        
        const newPost = {
            id: Date.now().toString(),
            title,
            content: cleanContent,
            author: req.user.username,
            timestamp: Date.now(),
            reactions: {
                heart: [],
                shocked: [],
                xoxo: []
            }
        };

        posts.push(newPost);
        fs.writeFileSync(POSTS_FILE, JSON.stringify(posts, null, 2));
        
        // Send email notification to all users about the new post
        if (isEmailSystemEnabled()) {
            try {
                const users = JSON.parse(fs.readFileSync(USERS_FILE));
                
                // Send notification to each user with an email
                users.forEach(async (user) => {
                    if (user.email) {
                        const notificationOptions = {
                            from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
                            to: user.email,
                            subject: `New Taunton Girl Post: ${title}`,
                            html: `
                                <!DOCTYPE html>
                                <html lang="en">
                                <head>
                                    <meta charset="UTF-8">
                                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                    <title>New Post - Taunton Girl</title>
                                    <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&family=Cormorant+Garamond:wght@400;600&display=swap" rel="stylesheet">
                                </head>
                                <body style="margin: 0; padding: 0; font-family: 'Cormorant Garamond', serif; color: #2C1810; background-color: #F7F3E3;">
                                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                                        <div style="text-align: center; margin-bottom: 30px;">
                                            <h1 style="font-family: 'Playfair Display', serif; color: #2C5530; margin: 0; font-size: 36px; font-weight: 700;">
                                                <span style="color: #C9A227;">✧</span> Taunton Girl <span style="color: #C9A227;">✧</span>
                                            </h1>
                                            <p style="font-style: italic; color: #1B4965; margin-top: 5px; font-size: 18px;">Your exclusive source into Somerset's finest</p>
                                        </div>
                                        
                                        <div style="background-color: #ffffff; border-left: 4px solid #2C5530; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(44, 85, 48, 0.2);">
                                            <h2 style="font-family: 'Playfair Display', serif; color: #1B4965; margin-top: 0; font-size: 26px; text-align: center;">
                                                Fresh Somerset Tea Just Poured
                                            </h2>
                                            
                                            <p style="font-size: 17px; line-height: 1.6; color: #2C1810; margin-bottom: 25px; font-weight: 500;">
                                                Darling ${user.username}, 
                                            </p>
                                            
                                            <p style="font-size: 17px; line-height: 1.6; color: #2C1810; margin-bottom: 25px; font-weight: 500;">
                                                The latest scoop from Somerset has just arrived, and you simply <em>must</em> read it immediately!
                                            </p>
                                            
                                            <div style="text-align: center; margin: 30px 0; padding: 20px; border: 2px dashed #C9A227; background-color: #FFFDF5; box-shadow: 0 4px 10px rgba(201, 162, 39, 0.1);">
                                                <h3 style="font-family: 'Playfair Display', serif; color: #2C5530; margin: 0; font-size: 24px; font-weight: 700;">
                                                    "${title}"
                                                </h3>
                                            </div>
                                            
                                            <div style="text-align: center; margin-top: 30px;">
                                                <a href="${process.env.SITE_URL || 'http://localhost:3000'}" style="display: inline-block; font-family: 'Playfair Display', serif; background-color: #2C5530; color: #F7F3E3; text-decoration: none; padding: 12px 25px; border-radius: 4px; font-size: 17px; font-weight: 600; box-shadow: 0 4px 6px rgba(44, 85, 48, 0.2);">
                                                    Read the Full Story
                                                </a>
                                            </div>
                                        </div>
                                        
                                        <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid rgba(44, 85, 48, 0.2);">
                                            <p style="font-style: italic; color: #C9A227; font-size: 20px; margin: 0; text-shadow: 0.5px 0.5px 1px rgba(0,0,0,0.1);">
                                                Kisses from the West Country,
                                            </p>
                                            <p style="font-family: 'Playfair Display', serif; color: #2C5530; font-size: 24px; margin: 5px 0 0 0; font-weight: 700;">
                                                Taunton Girl
                                            </p>
                                            <p style="font-family: 'Cormorant Garamond', serif; color: #1B4965; font-size: 16px; margin: 20px 0 0 0; font-weight: 500;">
                                                <em>Remember, in Somerset, every tale finds its way to Taunton Girl</em>
                                            </p>
                                            <p style="font-size: 13px; color: #555; margin-top: 20px; font-weight: 500;">
                                                To unsubscribe from these notifications, please update your profile settings.
                                            </p>
                                        </div>
                                    </div>
                                </body>
                                </html>
                            `
                        };
                        
                        try {
                            await sendEmail(notificationOptions);
                            console.log(`Notification email sent to ${user.email}`);
                        } catch (emailError) {
                            console.error(`Failed to send notification to ${user.email}:`, emailError);
                        }
                    }
                });
                
            } catch (emailError) {
                console.error('Error sending notification emails:', emailError);
                // Continue with the response even if emails fail
            }
        }
        
        res.render('create-post', { success: 'Post created successfully!', error: null });
    } catch (error) {
        res.render('create-post', { error: 'Failed to create post. Please try again.', success: null });
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
});

// Password reset routes
app.get('/forgot-password', (req, res) => {
    if (res.locals.user) {
        return res.redirect('/');
    }
    
    if (process.env.EMAIL_SYSTEM_ENABLED !== 'true') {
        return res.status(503).render('error', { 
            error: `Greetings from Taunton Girl!
            
Your trusted source for all the whispers and secrets of Somerset's finest.

The email system is taking a lovely countryside break at the moment, darling. Perhaps a stroll through Vivary Park might clear your mind?

Don't fret too much about your account - in a town where everyone knows everyone, secrets have a way of finding their way home...

Ta-ra! 🌸`
        });
    }
    
    res.render('forgot-password', { error: null, success: null });
});

app.post('/forgot-password', async (req, res) => {
    if (process.env.EMAIL_SYSTEM_ENABLED !== 'true') {
        return res.status(503).render('error', { 
            error: `Greetings from Taunton Girl!
            
Your trusted source for all the whispers and secrets of Somerset's finest.

The email system is taking a lovely countryside break at the moment, darling. Perhaps a stroll through Vivary Park might clear your mind?

Don't fret too much about your account - in a town where everyone knows everyone, secrets have a way of finding their way home...

Ta-ra! 🌸`
        });
    }
    
    try {
        const { email } = req.body;
        console.log('Password reset requested for email:', email);
        
        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        const user = users.find(u => u.email === email);
        console.log('User found:', user ? 'Yes' : 'No');

        if (!user) {
            return res.render('forgot-password', { 
                error: 'No account found with this email address.',
                success: null 
            });
        }

        const resetCode = generateResetCode();
        resetCodes.set(email, {
            code: resetCode,
            timestamp: Date.now(),
            userId: user.id
        });

        // Send email with reset code
        const mailOptions = {
            from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset Code - Taunton Girl XOXO',
            html: `
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Password Reset - Taunton Girl</title>
                    <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&family=Cormorant+Garamond:wght@400;600&display=swap" rel="stylesheet">
                </head>
                <body style="margin: 0; padding: 0; font-family: 'Cormorant Garamond', serif; color: #2C1810; background-color: #F7F3E3;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <div style="text-align: center; margin-bottom: 30px;">
                            <h1 style="font-family: 'Playfair Display', serif; color: #2C5530; margin: 0; font-size: 36px; font-weight: 700;">
                                <span style="color: #C9A227;">✧</span> Taunton Girl <span style="color: #C9A227;">✧</span>
                            </h1>
                            <p style="font-style: italic; color: #1B4965; margin-top: 5px; font-size: 18px;">Your exclusive source into Somerset's finest</p>
                        </div>
                        
                        <div style="background-color: #ffffff; border-left: 4px solid #2C5530; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(44, 85, 48, 0.2);">
                            <h2 style="font-family: 'Playfair Display', serif; color: #1B4965; margin-top: 0; font-size: 26px; text-align: center;">
                                Oh darling, forgot your password?
                            </h2>
                            
                            <p style="font-size: 17px; line-height: 1.6; color: #2C1810; margin-bottom: 25px; font-weight: 500;">
                                Well well well, ${user.username}... seems you've misplaced your key to our little world of Somerset whispers. Not to worry, we all have our forgetful moments – though Taunton Girl never forgets a juicy secret!
                            </p>
                            
                            <p style="font-size: 17px; line-height: 1.6; color: #2C1810; margin-bottom: 25px; font-weight: 500;">
                                Use this exclusive code to reset your password and regain access to all the Somerset tea:
                            </p>
                            
                            <div style="text-align: center; margin: 30px 0;">
                                <div style="background: linear-gradient(to right, #2C5530, #1B4965); padding: 3px; border-radius: 8px; box-shadow: 0 4px 10px rgba(44, 85, 48, 0.3);">
                                    <div style="background-color: #F7F3E3; padding: 20px; border-radius: 6px;">
                                        <h1 style="font-family: 'Playfair Display', serif; color: #C9A227; font-size: 32px; letter-spacing: 10px; margin: 0; font-weight: 700; text-shadow: 1px 1px 1px rgba(0,0,0,0.1);">
                                            ${resetCode}
                                        </h1>
                                    </div>
                                </div>
                                <p style="font-size: 15px; color: #1B4965; margin-top: 12px; font-style: italic; font-weight: 500;">
                                    This code will expire in 15 minutes, darling. Don't keep us waiting!
                                </p>
                            </div>
                            
                            <p style="font-size: 17px; line-height: 1.6; color: #2C1810; font-weight: 500;">
                                If you didn't request this reset, well... someone might be trying to peek at your messages. 
                                Best ignore this email – your secrets are safe with us.
                            </p>
                        </div>
                        
                        <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid rgba(44, 85, 48, 0.2);">
                            <p style="font-style: italic; color: #C9A227; font-size: 20px; margin: 0; text-shadow: 0.5px 0.5px 1px rgba(0,0,0,0.1);">
                                Kisses from the West Country,
                            </p>
                            <p style="font-family: 'Playfair Display', serif; color: #2C5530; font-size: 24px; margin: 5px 0 0 0; font-weight: 700;">
                                Taunton Girl
                            </p>
                            <p style="font-family: 'Cormorant Garamond', serif; color: #1B4965; font-size: 16px; margin: 20px 0 0 0; font-weight: 500;">
                                <em>Remember, in Somerset, every tale finds its way to Taunton Girl</em>
                            </p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        console.log('Attempting to send email to:', email);
        console.log('Using email provider:', emailProvider);

        await sendEmail(mailOptions);
        console.log('Email sent successfully');
        
        res.render('verify-code', { error: null, email });
    } catch (error) {
        console.error('Error in password reset:', error);
        res.render('forgot-password', { 
            error: `Failed to send reset code: ${error.message}`,
            success: null 
        });
    }
});

app.post('/verify-code', (req, res) => {
    if (!isEmailSystemEnabled()) {
        return res.render('error', { 
            error: `Greetings from Taunton Girl!
            
Your trusted source for all the whispers and secrets of Somerset's finest.

The email system is taking a lovely countryside break at the moment, darling. Perhaps a stroll through Vivary Park might clear your mind?

Don't fret too much about your account - in a town where everyone knows everyone, secrets have a way of finding their way home...

Ta-ra! 🌸`
        });
    }
    const { email, code } = req.body;
    const resetData = resetCodes.get(email);

    if (!resetData || resetData.code !== code) {
        return res.render('verify-code', { 
            error: 'Invalid or expired code. Please try again.',
            email 
        });
    }

    // Check if code is expired (15 minutes)
    if (Date.now() - resetData.timestamp > 15 * 60 * 1000) {
        resetCodes.delete(email);
        return res.render('verify-code', { 
            error: 'Code has expired. Please request a new one.',
            email 
        });
    }

    res.render('reset-password', { error: null, email, code });
});

app.post('/reset-password', async (req, res) => {
    if (!isEmailSystemEnabled()) {
        return res.render('error', { 
            error: `Greetings from Taunton Girl!
            
Your trusted source for all the whispers and secrets of Somerset's finest.

The email system is taking a lovely countryside break at the moment, darling. Perhaps a stroll through Vivary Park might clear your mind?

Don't fret too much about your account - in a town where everyone knows everyone, secrets have a way of finding their way home...

Ta-ra! 🌸`
        });
    }
    try {
        const { email, code, newPassword, confirmPassword } = req.body;
        const resetData = resetCodes.get(email);

        if (!resetData || resetData.code !== code) {
            return res.render('reset-password', { 
                error: 'Invalid or expired code. Please try again.',
                email,
                code 
            });
        }

        if (newPassword !== confirmPassword) {
            return res.render('reset-password', { 
                error: 'Passwords do not match.',
                email,
                code 
            });
        }

        const users = JSON.parse(fs.readFileSync(USERS_FILE));
        const userIndex = users.findIndex(u => u.id === resetData.userId);

        if (userIndex === -1) {
            return res.render('reset-password', { 
                error: 'User not found.',
                email,
                code 
            });
        }

        users[userIndex].password = await bcrypt.hash(newPassword, 10);
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        resetCodes.delete(email);

        // Log the user in automatically
        const token = jwt.sign(
            { id: users[userIndex].id, username: users[userIndex].username, isAdmin: users[userIndex].isAdmin },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        res.redirect('/');
    } catch (error) {
        res.render('reset-password', { 
            error: 'Failed to reset password. Please try again.',
            email,
            code 
        });
    }
});

// API routes for post reactions
app.post('/api/reactions', authenticateUser, (req, res) => {
    try {
        const { postId, reactionType } = req.body;
        
        // Validate reaction type
        if (!['heart', 'shocked', 'xoxo'].includes(reactionType)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid reaction type' 
            });
        }
        
        const posts = JSON.parse(fs.readFileSync(POSTS_FILE));
        const postIndex = posts.findIndex(p => p.id === postId);
        
        if (postIndex === -1) {
            return res.status(404).json({ 
                success: false, 
                message: 'Post not found' 
            });
        }
        
        // Initialize reactions object if it doesn't exist
        if (!posts[postIndex].reactions) {
            posts[postIndex].reactions = {};
        }
        
        // Initialize reaction type array if it doesn't exist
        if (!posts[postIndex].reactions[reactionType]) {
            posts[postIndex].reactions[reactionType] = [];
        }
        
        const userId = req.user.id;
        const userReactionIndex = posts[postIndex].reactions[reactionType].indexOf(userId);
        let added = false;
        
        // Toggle user's reaction
        if (userReactionIndex === -1) {
            // User hasn't reacted yet, add reaction
            posts[postIndex].reactions[reactionType].push(userId);
            added = true;
        } else {
            // User already reacted, remove reaction
            posts[postIndex].reactions[reactionType].splice(userReactionIndex, 1);
        }
        
        fs.writeFileSync(POSTS_FILE, JSON.stringify(posts, null, 2));
        
        res.json({
            success: true,
            count: posts[postIndex].reactions[reactionType].length,
            added
        });
    } catch (error) {
        console.error('Error handling reaction:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error processing reaction' 
        });
    }
});

// Invite system routes
app.post('/admin/invites/add', requireAdmin, (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !email.includes('@')) {
            return res.json({ success: false, message: 'Invalid email address' });
        }

        const invites = JSON.parse(fs.readFileSync(INVITES_FILE));
        
        // Check if email already exists in the invite list
        if (invites.some(invite => invite.email === email)) {
            return res.json({ success: false, message: 'Email already in invite list' });
        }

        const newInvite = {
            id: Date.now().toString(),
            email,
            addedBy: req.user.username,
            addedAt: Date.now()
        };

        invites.push(newInvite);
        fs.writeFileSync(INVITES_FILE, JSON.stringify(invites, null, 2));
        res.json({ success: true, invite: newInvite });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

app.delete('/admin/invites/:inviteId', requireAdmin, (req, res) => {
    try {
        const invites = JSON.parse(fs.readFileSync(INVITES_FILE));
        const filteredInvites = invites.filter(invite => invite.id !== req.params.inviteId);
        
        fs.writeFileSync(INVITES_FILE, JSON.stringify(filteredInvites, null, 2));
        res.json({ success: true });
    } catch (error) {
        res.json({ success: false, message: error.message });
    }
});

app.post('/admin/invites/send-all', requireAdmin, async (req, res) => {
    if (!isEmailSystemEnabled()) {
        return res.json({ 
            success: false, 
            message: 'Email system is disabled. Please enable it in your environment configuration.' 
        });
    }

    try {
        const invites = JSON.parse(fs.readFileSync(INVITES_FILE));
        
        if (invites.length === 0) {
            return res.json({ success: false, message: 'No invites to send' });
        }

        const accessPin = process.env.ACCESS_PIN;
        if (!accessPin) {
            return res.json({ success: false, message: 'ACCESS_PIN not set in environment variables' });
        }

        // Send emails to all invites
        let sentCount = 0;
        let failedEmails = [];

        for (const invite of invites) {
            try {
                const mailOptions = {
                    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
                    to: invite.email,
                    subject: 'Exclusive Invitation - Taunton Girl',
                    html: `
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Exclusive Invitation - Taunton Girl</title>
                            <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&family=Cormorant+Garamond:wght@400;600&display=swap" rel="stylesheet">
                        </head>
                        <body style="margin: 0; padding: 0; font-family: 'Cormorant Garamond', serif; color: #2C1810; background-color: #F7F3E3;">
                            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                                <div style="text-align: center; margin-bottom: 30px;">
                                    <h1 style="font-family: 'Playfair Display', serif; color: #2C5530; margin: 0; font-size: 36px; font-weight: 700;">
                                        <span style="color: #C9A227;">✧</span> Taunton Girl <span style="color: #C9A227;">✧</span>
                                    </h1>
                                    <p style="font-style: italic; color: #1B4965; margin-top: 5px; font-size: 18px;">Your exclusive source into Somerset's finest</p>
                                </div>
                                
                                <div style="background-color: #ffffff; border-left: 4px solid #2C5530; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(44, 85, 48, 0.2);">
                                    <h2 style="font-family: 'Playfair Display', serif; color: #1B4965; margin-top: 0; font-size: 26px; text-align: center;">
                                        A Most Exclusive Invitation
                                    </h2>
                                    
                                    <p style="font-size: 17px; line-height: 1.6; color: #2C1810; margin-bottom: 25px; font-weight: 500;">
                                        Darling, 
                                    </p>
                                    
                                    <p style="font-size: 17px; line-height: 1.6; color: #2C1810; margin-bottom: 25px; font-weight: 500;">
                                        Word has reached Taunton Girl that you are just the sort of discerning individual who appreciates the finer whispers of Somerset society. How fortunate that our paths should cross!
                                    </p>
                                    
                                    <p style="font-size: 17px; line-height: 1.6; color: #2C1810; margin-bottom: 25px; font-weight: 500;">
                                        I am <em>personally</em> extending an invitation for you to join our exclusive circle of confidants. Together, we'll share the delicious tales that make Somerset's social scene simply <em>divine</em>.
                                    </p>
                                    
                                    <div style="text-align: center; margin: 30px 0;">
                                        <div style="background: linear-gradient(to right, #2C5530, #1B4965); padding: 3px; border-radius: 8px; box-shadow: 0 4px 10px rgba(44, 85, 48, 0.3);">
                                            <div style="background-color: #F7F3E3; padding: 20px; border-radius: 6px;">
                                                <p style="font-family: 'Cormorant Garamond', serif; color: #1B4965; font-size: 18px; margin: 0 0 15px 0; font-weight: 500;">
                                                    Your exclusive access code:
                                                </p>
                                                <h1 style="font-family: 'Playfair Display', serif; color: #C9A227; font-size: 32px; letter-spacing: 3px; margin: 0; font-weight: 700; text-shadow: 1px 1px 1px rgba(0,0,0,0.1);">
                                                    ${accessPin}
                                                </h1>
                                            </div>
                                        </div>
                                        <p style="font-size: 15px; color: #1B4965; margin-top: 12px; font-style: italic; font-weight: 500;">
                                            This is your key to the inner circle. Guard it well.
                                        </p>
                                    </div>
                                    
                                    <p style="font-size: 17px; line-height: 1.6; color: #2C1810; font-weight: 500;">
                                        To join our society, simply visit: 
                                    </p>
                                    
                                    <div style="text-align: center; margin: 25px 0; padding: 15px; background-color: #F0F8FF; border: 1px solid #2C5530; border-radius: 6px;">
                                        <p style="font-family: 'Courier New', monospace; font-size: 16px; color: #2C5530; margin: 0; word-break: break-all;">
                                            ${process.env.SITE_URL || 'http://localhost:3000'}
                                        </p>
                                    </div>
                                    
                                    <p style="font-size: 17px; line-height: 1.6; color: #2C1810; font-weight: 500;">
                                        and enter this exclusive code when prompted.
                                    </p>
                                    
                                    <p style="font-size: 17px; line-height: 1.6; color: #2C1810; font-weight: 500; margin-top: 20px;">
                                        Do hurry, darling. In Somerset, the most delicious gossip never waits.
                                    </p>

                                     <p style="font-size: 16px; line-height: 1.4; color: #2C1810; font-style: italic; margin-bottom: 15px; background-color: #FFF8E8; padding: 10px; border-left: 2px solid #C9A227;">
                                        <em>Note: Our site is currently blocked on school WiFi, darling. Our friends in IT promise a fix in the coming weeks.</em>
                                    </p>
                                </div>
                                
                                <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid rgba(44, 85, 48, 0.2);">
                                    <p style="font-style: italic; color: #C9A227; font-size: 20px; margin: 0; text-shadow: 0.5px 0.5px 1px rgba(0,0,0,0.1);">
                                        Kisses from the West Country,
                                    </p>
                                    <p style="font-family: 'Playfair Display', serif; color: #2C5530; font-size: 24px; margin: 5px 0 0 0; font-weight: 700;">
                                        Taunton Girl
                                    </p>
                                    <p style="font-family: 'Cormorant Garamond', serif; color: #1B4965; font-size: 16px; margin: 20px 0 0 0; font-weight: 500;">
                                        <em>Remember, in Somerset, every tale finds its way to Taunton Girl</em>
                                    </p>
                                </div>
                            </div>
                        </body>
                        </html>
                    `
                };
                
                await sendEmail(mailOptions);
                sentCount++;
            } catch (emailError) {
                console.error(`Failed to send invitation to ${invite.email}:`, emailError);
                failedEmails.push(invite.email);
            }
        }

        if (sentCount === 0) {
            return res.json({ 
                success: false, 
                message: 'Failed to send any invitations. Please check the email configuration.' 
            });
        }

        res.json({ 
            success: true, 
            message: `Successfully sent ${sentCount} invitations${failedEmails.length > 0 ? ` (${failedEmails.length} failed)` : ''}` 
        });
    } catch (error) {
        console.error('Error sending invitations:', error);
        res.json({ success: false, message: error.message });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
}); 