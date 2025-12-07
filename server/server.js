const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

const {
    getUsers,
    getUserByUsername,
    getUserWithPassword,
    getUserById,
    updateUserLastLogin,
    initializeDatabase,
    getStats,
    getAllegations,
    getAllegationById,
    createAllegation,
    updateAllegation,
    deleteAllegation,
    getPublicAllegations,
    // Session management imports
    getActiveSession,
    setActiveSession,
    clearActiveSession,
    isSessionActive,
    isUserAlreadyLoggedIn
} = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize database on startup
initializeDatabase().catch(console.error);

// Enhanced CORS for mobile - MUST come before session
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
    optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../public')));

// Enhanced Session configuration for mobile compatibility
app.use(session({
    name: 'islamInNepal.sid',
    secret: process.env.SESSION_SECRET || 'islam-in-nepal-secure-key-2025-enhanced-mobile',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        secure: false, // Set to false for development
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax', // Use 'lax' for better mobile compatibility
        path: '/'
    },
    store: new session.MemoryStore({
        checkPeriod: 86400000
    })
}));

app.use((req, res, next) => {
    const userAgent = req.headers['user-agent'] || '';
    const isMobile = /Mobile|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
    req.isMobile = isMobile;

    // Enhanced session logging for debugging
    console.log('=== SESSION DEBUG ===');
    console.log('IP:', req.ip);
    console.log('Has User:', !!req.session?.user);
    console.log('=====================');

    next();
});

// Enhanced Rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    message: {
        success: false,
        message: 'Too many login attempts, please try again later.'
    }
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100
});

// Enhanced Authentication middleware with mobile support
const requireAuth = async (req, res, next) => {
    if (req.session.user) {
        try {
            // Verify user still exists and session is active
            const user = await getUserById(req.session.user.id);
            const activeSession = getActiveSession();

            if (user && activeSession && activeSession.sessionId === req.sessionID) {
                console.log(`✅ Auth successful for user: ${user.username} on ${req.isMobile ? 'mobile' : 'desktop'}`);
                next();
            } else {
                // Session is invalid or another session is active
                console.log(`❌ Session invalid - Active: ${activeSession?.sessionId}, Current: ${req.sessionID}`);
                req.session.destroy();
                clearActiveSession();
                res.status(401).json({
                    success: false,
                    message: 'Session expired or another session is active. Please login again.'
                });
            }
        } catch (error) {
            console.error('Auth middleware error:', error);
            req.session.destroy();
            clearActiveSession();
            res.status(500).json({
                success: false,
                message: 'Authentication error'
            });
        }
    } else {
        console.log('❌ No session user found');
        res.status(401).json({
            success: false,
            message: 'Authentication required'
        });
    }
};

// Quran data
let quranData = null;

// Load Quran data
async function loadQuranData() {
    try {
        const fs = require('fs').promises;
        const quranPath = path.join(__dirname, 'data', 'quran.json');
        const data = await fs.readFile(quranPath, 'utf8');
        quranData = JSON.parse(data);
        console.log('✅ Quran data loaded successfully');
    } catch (error) {
        console.error('❌ Error loading Quran data:', error);
        quranData = { chapters: [] };
    }
}

// Load Quran data on server start
loadQuranData();

// Enhanced Routes

// Serve main site
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Serve admin panel
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/admin.html'));
});

// API Routes

// Quran API endpoints
app.get('/api/quran/chapters', (req, res) => {
    if (!quranData) {
        return res.status(503).json({
            success: false,
            message: 'Quran data not loaded yet'
        });
    }

    const chapters = quranData.chapters.map(chapter => ({
        chapterNumber: chapter.chapterNumber,
        chapterName: chapter.chapterName,
        chapterNameArabic: chapter.chapterNameArabic,
        totalVerses: chapter.verses.length
    }));

    res.json({
        success: true,
        data: chapters
    });
});

app.get('/api/quran/chapter/:chapterNumber', (req, res) => {
    if (!quranData) {
        return res.status(503).json({
            success: false,
            message: 'Quran data not loaded yet'
        });
    }

    const chapterNumber = parseInt(req.params.chapterNumber);
    const chapter = quranData.chapters.find(ch => ch.chapterNumber === chapterNumber);

    if (!chapter) {
        return res.status(404).json({
            success: false,
            message: 'Chapter not found'
        });
    }

    res.json({
        success: true,
        data: chapter
    });
});

app.get('/api/quran/verse/:chapterNumber/:verseNumber', (req, res) => {
    if (!quranData) {
        return res.status(503).json({
            success: false,
            message: 'Quran data not loaded yet'
        });
    }

    const chapterNumber = parseInt(req.params.chapterNumber);
    const verseNumber = parseInt(req.params.verseNumber);

    const chapter = quranData.chapters.find(ch => ch.chapterNumber === chapterNumber);

    if (!chapter) {
        return res.status(404).json({
            success: false,
            message: 'Chapter not found'
        });
    }

    const verse = chapter.verses.find(v => v.verseNumber === verseNumber);

    if (!verse) {
        return res.status(404).json({
            success: false,
            message: 'Verse not found'
        });
    }

    res.json({
        success: true,
        data: {
            chapterNumber: chapter.chapterNumber,
            chapterName: chapter.chapterName,
            chapterNameArabic: chapter.chapterNameArabic,
            verse: verse
        }
    });
});

// Enhanced Authentication with mobile session support
app.post('/api/login', loginLimiter, [
    body('username').trim().isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: errors.array()[0].msg
            });
        }

        const { username, password } = req.body;
        const user = await getUserWithPassword(username);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // SINGLE SESSION ENFORCEMENT: Check if user is already logged in
        const existingSession = getActiveSession();
        if (existingSession && existingSession.userId === user.id) {
            console.log(`🚫 User ${user.username} already has active session: ${existingSession.sessionId}`);
            return res.status(409).json({
                success: false,
                message: 'User is already logged in from another device/session. Please logout from the other session first.'
            });
        }

        // Update last login
        await updateUserLastLogin(user.id);

        // Create session and set as active
        req.session.user = {
            id: user.id,
            username: user.username,
            fullName: user.fullName,
            role: user.role
        };

        // Set this as the active session
        setActiveSession(req.sessionID, user.id);
        // Force session save with callback to ensure it's saved
        req.session.save((err) => {
            if (err) {
                console.error('❌ Session save error:', err);
                clearActiveSession();
                return res.status(500).json({
                    success: false,
                    message: 'Login failed due to session error'
                });
            }

            console.log('✅ Login successful - Session saved');

            res.json({
                success: true,
                message: 'Login successful',
                user: {
                    id: user.id,
                    username: user.username,
                    fullName: user.fullName,
                    role: user.role
                },
                redirectUrl: '/admin' // Explicitly provide redirect URL
            });
        });

    } catch (error) {
        console.error('❌ Login error:', error);
        clearActiveSession();
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.post('/api/logout', (req, res) => {
    const sessionId = req.sessionID;
    console.log(`🔒 Logging out session: ${sessionId} from ${req.isMobile ? 'mobile' : 'desktop'}`);

    req.session.destroy((err) => {
        if (err) {
            console.error('❌ Session destroy error:', err);
            return res.status(500).json({
                success: false,
                message: 'Logout failed'
            });
        }
        // Clear active session
        clearActiveSession();
        res.clearCookie('islamInNepal.sid');
        res.json({
            success: true,
            message: 'Logout successful'
        });
    });
});

app.get('/api/user', async (req, res) => {

    if (req.session.user) {
        try {
            const user = await getUserById(req.session.user.id);
            const activeSession = getActiveSession();

            if (user && activeSession && activeSession.sessionId === req.sessionID) {
                res.json({
                    success: true,
                    user: {
                        id: user.id,
                        username: user.username,
                        fullName: user.fullName,
                        role: user.role
                    }
                });
            } else {
                // Session is invalid
                console.log(`❌ User session invalid - User: ${user?.username}, Session mismatch`);
                req.session.destroy();
                clearActiveSession();
                res.status(401).json({
                    success: false,
                    user: null
                });
            }
        } catch (error) {
            console.error('❌ User endpoint error:', error);
            res.status(401).json({
                success: false,
                user: null
            });
        }
    } else {
        console.log('❌ No user in session');
        res.status(401).json({
            success: false,
            user: null
        });
    }
});

// Force logout endpoint (for admin to clear any stuck sessions)
app.post('/api/force-logout', async (req, res) => {
    console.log('🔄 Force logout called - clearing all sessions');
    clearActiveSession();
    res.json({
        success: true,
        message: 'All sessions cleared'
    });
});

// Admin verification endpoint
app.get('/api/admin/verify', requireAuth, async (req, res) => {
    try {
        console.log(`✅ Admin verification successful for: ${req.session.user.username}`);
        res.json({
            success: true,
            user: req.session.user
        });
    } catch (error) {
        console.error('❌ Verify admin error:', error);
        res.status(401).json({
            success: false,
            message: 'Authentication failed'
        });
    }
});

// Stats API
app.get('/api/stats', requireAuth, async (req, res) => {
    try {
        const stats = await getStats();
        res.json({
            success: true,
            data: stats
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch stats'
        });
    }
});

app.get('/api/clarifications', async (req, res) => {
    try {
        const data = await getPublicAllegations();

        // Add caching headers to reduce unnecessary reloads
        res.set({
            'Cache-Control': 'public, max-age=60',
            'ETag': `"${Date.now()}"`
        });

        res.json(data);
    } catch (error) {
        console.error('Get public clarifications error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch clarifications',
            data: []
        });
    }
});

// Allegations API (Admin only)
app.get('/api/allegations', requireAuth, async (req, res) => {
    try {
        const { page = 1, limit = 20, search = '' } = req.query;
        const allegations = await getAllegations(parseInt(page), parseInt(limit), search);
        res.json({
            success: true,
            ...allegations
        });
    } catch (error) {
        console.error('Get allegations error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch allegations',
            items: [],
            total: 0,
            page: 1,
            totalPages: 0
        });
    }
});

app.post('/api/allegations', requireAuth, [
    body('title').trim().isLength({ min: 5 }).withMessage('Title must be at least 5 characters'),
    body('description').trim().isLength({ min: 20 }).withMessage('Description must be at least 20 characters')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: errors.array()[0].msg
            });
        }

        const allegation = await createAllegation(req.body, req.session.user.id);
        res.json({
            success: true,
            message: 'Clarification created successfully',
            data: allegation
        });
    } catch (error) {
        console.error('Create allegation error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create clarification'
        });
    }
});

app.put('/api/allegations/:id', requireAuth, [
    body('title').optional().trim().isLength({ min: 5 }).withMessage('Title must be at least 5 characters'),
    body('description').optional().trim().isLength({ min: 20 }).withMessage('Description must be at least 20 characters')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: errors.array()[0].msg
            });
        }

        const allegation = await updateAllegation(req.params.id, req.body, req.session.user.id);
        if (!allegation) {
            return res.status(404).json({
                success: false,
                message: 'Clarification not found'
            });
        }

        res.json({
            success: true,
            message: 'Clarification updated successfully',
            data: allegation
        });
    } catch (error) {
        console.error('Update allegation error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update clarification'
        });
    }
});

app.patch('/api/allegations/:id/status', requireAuth, [
    body('status').isIn(['published', 'draft']).withMessage('Status must be published or draft')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: errors.array()[0].msg
            });
        }

        const { status } = req.body;
        const allegation = await updateAllegation(req.params.id, { status }, req.session.user.id);

        if (!allegation) {
            return res.status(404).json({
                success: false,
                message: 'Clarification not found'
            });
        }

        res.json({
            success: true,
            message: `Clarification ${status === 'published' ? 'published' : 'unpublished'} successfully`,
            data: allegation
        });
    } catch (error) {
        console.error('Update allegation status error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update clarification status'
        });
    }
});

app.delete('/api/allegations/:id', requireAuth, async (req, res) => {
    try {
        const deleted = await deleteAllegation(req.params.id);
        if (!deleted) {
            return res.status(404).json({
                success: false,
                message: 'Clarification not found'
            });
        }

        res.json({
            success: true,
            message: 'Clarification deleted successfully'
        });
    } catch (error) {
        console.error('Delete allegation error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete clarification'
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        service: 'Islam in Nepal API',
        activeSession: getActiveSession() ? 'Yes' : 'No',
        mobile: req.isMobile
    });
});

// Session debug endpoint
app.get('/api/debug/session', (req, res) => {
    res.json({
        sessionExists: !!req.session,
        user: req.session.user,
        sessionID: req.sessionID,
        activeSession: getActiveSession(),
        isMobile: req.isMobile,
        headers: {
            'user-agent': req.headers['user-agent'],
            'cookie': req.headers.cookie ? 'present' : 'missing'
        }
    });
});

// Clear all sessions endpoint (for development)
app.post('/api/clear-sessions', (req, res) => {
    console.log('🔄 Clearing all sessions');
    clearActiveSession();
    res.json({
        success: true,
        message: 'All sessions cleared'
    });
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'API endpoint not found'
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log('🚀 Islam in Nepal Server Running');
    console.log(`📍 http://localhost:${PORT}`);
    console.log(`🔍 Health: http://localhost:${PORT}/api/health`);
    console.log(`📖 Quran API: http://localhost:${PORT}/api/quran/chapters`);
    console.log(`🛠️  Session Debug: http://localhost:${PORT}/api/debug/session`);
    console.log('✅ Server is ready with Quran reader!');
});

// Helper function to get IP address
function getIPAddress() {
    const interfaces = require('os').networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const interface of interfaces[name]) {
            if (interface.family === 'IPv4' && !interface.internal) {
                return interface.address;
            }
        }
    }
    return 'localhost';
}

// Add security middleware
app.use((req, res, next) => {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

    next();
});

// Enhanced rate limiting for Quran API
const quranLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        success: false,
        message: 'Too many requests, please try again later.'
    }
});

app.use('/api/quran/*', quranLimiter);