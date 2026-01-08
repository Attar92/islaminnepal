const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'data', 'db.json');
const USERS_PATH = path.join(__dirname, 'data', 'users.json');
const QUESTIONS_PATH = path.join(__dirname, 'data', 'questions.json');

// session tracking for single session enforcement
let activeSession = null;
const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24 hours

// Ensure data directory exists
async function ensureDataDirectory() {
    try {
        await fs.mkdir(path.dirname(DB_PATH), { recursive: true });
    } catch (error) {
        console.error('Error creating data directory:', error);
    }
}

// Initialize database with single admin user
async function initializeDatabase() {
    try {
        await ensureDataDirectory();

        // Single admin user only
        const defaultUsers = [
            {
                id: 1,
                username: 'admin',
                password: await bcrypt.hash('admin123', 12),
                fullName: 'System Administrator',
                role: 'admin',
                createdAt: new Date().toISOString(),
                lastLogin: null
            }
        ];

        // Always recreate users file with only admin
        await fs.writeFile(USERS_PATH, JSON.stringify(defaultUsers, null, 2));

        // Database with sample clarifications
        const defaultData = {
            allegations: [
                {
                    id: 1,
                    title: "Islam promotes peace, not violence",
                    description: "Islam is fundamentally a religion of peace. The Quran emphasizes peace, mercy, and justice. The word 'Islam' itself comes from 'Salaam' meaning peace. Verses about fighting are often taken out of context - they were revealed during specific historical circumstances of defense against persecution.",
                    reference: "Quran 5:32: 'Whoever kills a soul... it is as if he had slain mankind entirely.' Quran 2:190: 'Fight in the way of Allah those who fight you but do not transgress.'",
                    status: "published",
                    createdBy: "System Administrator",
                    lastUpdatedBy: "System Administrator",
                    createdAt: new Date().toISOString(),
                    updatedAt: new Date().toISOString()
                },
                {
                    id: 2,
                    title: "Women's rights in Islam",
                    description: "Contrary to popular belief, Islam granted women rights 1400 years ago that were revolutionary for their time. Women in Islam have the right to education, property ownership, business, and choice in marriage. The Prophet Muhammad (PBUH) said: 'Seeking knowledge is obligatory for every Muslim (male and female).'",
                    reference: "Quran 4:1: 'O mankind, fear your Lord, who created you from one soul...' Quran 33:35: 'For Muslim men and women... for them Allah has prepared forgiveness and great reward.'",
                    status: "published",
                    createdBy: "System Administrator",
                    lastUpdatedBy: "System Administrator",
                    createdAt: new Date().toISOString(),
                    updatedAt: new Date().toISOString()
                }
            ]
        };

        // Always recreate database with fresh data
        await fs.writeFile(DB_PATH, JSON.stringify(defaultData, null, 2));

    } catch (error) {
        console.error('❌ Error initializing database:', error);
        throw error;
    }
}

// Enhanced Session management functions with timeout checking
function getActiveSession() {
    // Check if session has timed out
    if (activeSession && (Date.now() - activeSession.timestamp) > SESSION_TIMEOUT) {
        activeSession = null;
    }
    return activeSession;
}

function setActiveSession(sessionId, userId) {
    activeSession = {
        sessionId,
        userId,
        timestamp: Date.now(),
        createdAt: new Date().toISOString()
    };
}

function clearActiveSession() {
    activeSession = null;
}

function isSessionActive(sessionId) {
    const session = getActiveSession();
    return session && session.sessionId === sessionId;
}

function isUserAlreadyLoggedIn(userId) {
    const session = getActiveSession();
    return session && session.userId === userId;
}

// Clean up expired sessions periodically
setInterval(() => {
    getActiveSession(); // automatically clears expired sessions
}, 60000); // Check every min

// functions to read/write data
async function readData() {
    try {
        await ensureDataDirectory();
        const data = await fs.readFile(DB_PATH, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return { allegations: [] };
    }
}

async function writeData(data) {
    await ensureDataDirectory();
    await fs.writeFile(DB_PATH, JSON.stringify(data, null, 2));
}

async function readUsers() {
    try {
        await ensureDataDirectory();
        const data = await fs.readFile(USERS_PATH, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
}

async function writeUsers(users) {
    await ensureDataDirectory();
    await fs.writeFile(USERS_PATH, JSON.stringify(users, null, 2));
}

// Enhanced User functions
async function getUsers() {
    return await readUsers();
}

async function getUserByUsername(username) {
    const users = await readUsers();
    const user = users.find(user => user.username === username);

    // Don't return password in user object
    if (user) {
        const { password, ...userWithoutPassword } = user;
        return userWithoutPassword;
    }
    return null;
}

async function getUserWithPassword(username) {
    const users = await readUsers();
    return users.find(user => user.username === username);
}

async function getUserById(id) {
    const users = await readUsers();
    const user = users.find(user => user.id === parseInt(id));
    if (user) {
        const { password, ...userWithoutPassword } = user;
        return userWithoutPassword;
    }
    return null;
}

async function updateUserLastLogin(userId) {
    try {
        const users = await readUsers();
        const userIndex = users.findIndex(user => user.id === parseInt(userId));

        if (userIndex !== -1) {
            users[userIndex].lastLogin = new Date().toISOString();
            await writeUsers(users);
        }
    } catch (error) {
        console.error('Error updating user last login:', error);
    }
}

// Stats functions
async function getStats() {
    try {
        const data = await readData();
        const allegations = data.allegations || [];

        const totalAllegations = allegations.length;
        const publishedAllegations = allegations.filter(a => a.status === 'published').length;
        const draftAllegations = allegations.filter(a => a.status === 'draft').length;

        // Recent activity (last 7 days)
        const oneWeekAgo = new Date();
        oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

        const recentAllegations = allegations.filter(a => {
            try {
                return new Date(a.updatedAt) > oneWeekAgo;
            } catch (error) {
                return false;
            }
        }).length;

        return {
            totalAllegations,
            publishedAllegations,
            draftAllegations,
            recentAllegations
        };
    } catch (error) {
        console.error('Error getting stats:', error);
        return {
            totalAllegations: 0,
            publishedAllegations: 0,
            draftAllegations: 0,
            recentAllegations: 0
        };
    }
}

// Enhanced Allegation functions with full user tracking
async function getAllegations(page = 1, limit = 20, search = '') {
    try {
        const data = await readData();
        let allegations = data.allegations || [];

        // Filter by search term
        if (search) {
            allegations = allegations.filter(item =>
                item.title.toLowerCase().includes(search.toLowerCase()) ||
                item.description.toLowerCase().includes(search.toLowerCase()) ||
                (item.reference && item.reference.toLowerCase().includes(search.toLowerCase()))
            );
        }

        // Sort by creation date (newest first)
        allegations.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        // Pagination
        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;
        const paginatedItems = allegations.slice(startIndex, endIndex);

        return {
            items: paginatedItems,
            total: allegations.length,
            page,
            totalPages: Math.ceil(allegations.length / limit)
        };
    } catch (error) {
        console.error('Error getting allegations:', error);
        return {
            items: [],
            total: 0,
            page: 1,
            totalPages: 0
        };
    }
}

async function getAllegationById(id) {
    try {
        const data = await readData();
        return (data.allegations || []).find(item => item.id === parseInt(id));
    } catch (error) {
        console.error('Error getting allegation by ID:', error);
        return null;
    }
}

async function createAllegation(allegationData, userId) {
    try {
        const data = await readData();
        const allegations = data.allegations || [];
        const user = await getUserById(userId);

        const newAllegation = {
            id: Date.now(),
            status: allegationData.status || 'draft',
            title: allegationData.title,
            description: allegationData.description,
            reference: allegationData.reference || '',
            createdBy: user ? user.fullName : 'System Administrator',
            lastUpdatedBy: user ? user.fullName : 'System Administrator',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        allegations.push(newAllegation);
        data.allegations = allegations;
        await writeData(data);

        return newAllegation;
    } catch (error) {
        console.error('Error creating allegation:', error);
        throw error;
    }
}

async function updateAllegation(id, allegationData, userId) {
    try {
        const data = await readData();
        const allegations = data.allegations || [];
        const index = allegations.findIndex(item => item.id === parseInt(id));
        const user = await getUserById(userId);

        if (index === -1) return null;

        allegations[index] = {
            ...allegations[index],
            ...allegationData,
            lastUpdatedBy: user ? user.fullName : 'System Administrator',
            updatedAt: new Date().toISOString()
        };

        data.allegations = allegations;
        await writeData(data);

        return allegations[index];
    } catch (error) {
        console.error('Error updating allegation:', error);
        throw error;
    }
}

async function deleteAllegation(id) {
    try {
        const data = await readData();
        const allegations = data.allegations || [];
        const index = allegations.findIndex(item => item.id === parseInt(id));

        if (index === -1) return false;

        allegations.splice(index, 1);
        data.allegations = allegations;
        await writeData(data);

        return true;
    } catch (error) {
        console.error('Error deleting allegation:', error);
        throw error;
    }
}

// Get all published allegations for public website
async function getPublicAllegations() {
    try {
        const data = await readData();
        const allegations = data.allegations || [];

        return {
            success: true,
            data: allegations.filter(a => a.status === 'published'),
            lastUpdated: new Date().toISOString()
        };
    } catch (error) {
        console.error('Error getting public allegations:', error);
        return {
            success: false,
            data: [],
            lastUpdated: new Date().toISOString()
        };
    }
}


// Question functions
async function getQuestions() {
    try {
        await ensureDataDirectory();
        const data = await fs.readFile(QUESTIONS_PATH, 'utf8');
        const questions = JSON.parse(data);
        return questions.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    } catch (error) {
        return [];
    }
}

async function saveQuestions(questions) {
    await ensureDataDirectory();
    await fs.writeFile(QUESTIONS_PATH, JSON.stringify(questions, null, 2));
}

async function addQuestion(questionData) {
    try {
        const questions = await getQuestions();
        const newQuestion = {
            id: Date.now(),
            ...questionData,
            status: 'unread',
            createdAt: new Date().toISOString()
        };
        questions.push(newQuestion);
        await saveQuestions(questions);
        return newQuestion;
    } catch (error) {
        console.error('Error adding question:', error);
        throw error;
    }
}

async function deleteQuestion(questionId) {
    try {
        const questions = await getQuestions();
        const filteredQuestions = questions.filter(q => q.id !== parseInt(questionId));
        await saveQuestions(filteredQuestions);
        return true;
    } catch (error) {
        console.error('Error deleting question:', error);
        throw error;
    }
}

async function getQuestionStats() {
    try {
        const questions = await getQuestions();
        const total = questions.length;
        const unread = questions.filter(q => q.status === 'unread').length;
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const todayQuestions = questions.filter(q => {
            const questionDate = new Date(q.createdAt);
            return questionDate >= today;
        }).length;

        return { total, unread, todayQuestions };
    } catch (error) {
        console.error('Error getting question stats:', error);
        return { total: 0, unread: 0, todayQuestions: 0 };
    }
}

module.exports = {
    initializeDatabase,
    getUsers,
    getUserByUsername,
    getUserWithPassword,
    getUserById,
    updateUserLastLogin,
    getStats,
    getAllegations,
    getAllegationById,
    createAllegation,
    updateAllegation,
    deleteAllegation,
    getPublicAllegations,
    // Session management exports
    getActiveSession,
    setActiveSession,
    clearActiveSession,
    isSessionActive,
    isUserAlreadyLoggedIn,
    getQuestions,
    addQuestion,
    deleteQuestion,
    getQuestionStats
};