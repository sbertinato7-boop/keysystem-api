const express = require('express');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// ========== CONFIG ==========
const SECRET_KEY = crypto.randomBytes(32).toString('hex'); // Generate once, save in .env
const MONGO_URI = process.env.MONGO_URI; // Add in Glitch .env file
const KEY_EXPIRY_HOURS = 24;

let db;
MongoClient.connect(MONGO_URI, { useUnifiedTopology: true })
    .then(client => {
        db = client.db('keysystem');
        console.log('✅ Connected to MongoDB');
    })
    .catch(err => console.error('❌ MongoDB error:', err));

// ========== HELPER FUNCTIONS ==========
function generateHWID(ip, userAgent) {
    return crypto.createHash('sha256')
        .update(ip + userAgent)
        .digest('hex');
}

function signData(data) {
    return crypto.createHmac('sha256', SECRET_KEY)
        .update(JSON.stringify(data))
        .digest('hex');
}

function verifySignature(data, signature) {
    const expectedSignature = signData(data);
    return crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
    );
}

function generateKey() {
    return crypto.randomBytes(16).toString('hex').toUpperCase();
}

// ========== ROUTES ==========

// START SESSION - Checkpoint 1
app.post('/api/start', async (req, res) => {
    try {
        const hwid = generateHWID(req.ip, req.headers['user-agent']);
        const sessionId = crypto.randomBytes(16).toString('hex');
        const timestamp = Date.now();
        
        const session = {
            sessionId,
            hwid,
            timestamp,
            checkpoints: [],
            completed: false
        };
        
        await db.collection('sessions').insertOne(session);
        
        const signature = signData({ sessionId, hwid, timestamp });
        
        res.json({
            success: true,
            sessionId,
            signature,
            timestamp,
            message: 'Session started. Complete checkpoints to get key.'
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// VERIFY CHECKPOINT - Checkpoints 2 & 3
app.post('/api/checkpoint', async (req, res) => {
    try {
        const { sessionId, signature, checkpointId, proof } = req.body;
        
        if (!sessionId || !signature || !checkpointId) {
            return res.status(400).json({ success: false, error: 'Missing parameters' });
        }
        
        const session = await db.collection('sessions').findOne({ sessionId });
        
        if (!session) {
            return res.status(404).json({ success: false, error: 'Invalid session' });
        }
        
        // Verify signature
        if (!verifySignature({ sessionId, hwid: session.hwid }, signature)) {
            return res.status(403).json({ success: false, error: 'Invalid signature' });
        }
        
        // Check if already completed this checkpoint
        if (session.checkpoints.includes(checkpointId)) {
            return res.json({ success: true, message: 'Checkpoint already completed' });
        }
        
        // Validate checkpoint proof (customize based on your tasks)
        // Example: if checkpointId is 'task1', verify proof is correct
        
        await db.collection('sessions').updateOne(
            { sessionId },
            { $push: { checkpoints: checkpointId } }
        );
        
        const newSignature = signData({ sessionId, hwid: session.hwid, checkpoint: checkpointId });
        
        res.json({
            success: true,
            message: `Checkpoint ${checkpointId} completed`,
            signature: newSignature,
            checkpointsCompleted: session.checkpoints.length + 1
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// GET FINAL KEY - Checkpoint 4
app.post('/api/getkey', async (req, res) => {
    try {
        const { sessionId, signature } = req.body;
        
        if (!sessionId || !signature) {
            return res.status(400).json({ success: false, error: 'Missing parameters' });
        }
        
        const session = await db.collection('sessions').findOne({ sessionId });
        
        if (!session) {
            return res.status(404).json({ success: false, error: 'Invalid session' });
        }
        
        // Verify signature
        if (!verifySignature({ sessionId, hwid: session.hwid }, signature)) {
            return res.status(403).json({ success: false, error: 'Invalid signature' });
        }
        
        // Check if all required checkpoints completed
        const requiredCheckpoints = ['task1', 'task2']; // Customize
        const hasAllCheckpoints = requiredCheckpoints.every(cp => 
            session.checkpoints.includes(cp)
        );
        
        if (!hasAllCheckpoints) {
            return res.status(403).json({ 
                success: false, 
                error: 'Not all checkpoints completed',
                completed: session.checkpoints,
                required: requiredCheckpoints
            });
        }
        
        // Generate key
        const key = generateKey();
        const expiresAt = Date.now() + (KEY_EXPIRY_HOURS * 60 * 60 * 1000);
        
        await db.collection('keys').insertOne({
            key,
            hwid: session.hwid,
            sessionId,
            createdAt: Date.now(),
            expiresAt,
            used: false
        });
        
        // Mark session as completed
        await db.collection('sessions').updateOne(
            { sessionId },
            { $set: { completed: true, key } }
        );
        
        res.json({
            success: true,
            key,
            expiresAt,
            message: 'Key generated successfully'
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// VERIFY KEY - Called from Roblox
app.post('/api/verify', async (req, res) => {
    try {
        const { key, hwid } = req.body;
        
        if (!key || !hwid) {
            return res.status(400).json({ success: false, error: 'Missing parameters' });
        }
        
        const keyDoc = await db.collection('keys').findOne({ key });
        
        if (!keyDoc) {
            return res.json({ success: false, error: 'Invalid key' });
        }
        
        if (keyDoc.hwid !== hwid) {
            return res.json({ success: false, error: 'HWID mismatch' });
        }
        
        if (keyDoc.expiresAt < Date.now()) {
            return res.json({ success: false, error: 'Key expired' });
        }
        
        if (keyDoc.used) {
            return res.json({ success: false, error: 'Key already used' });
        }
        
        // Mark key as used
        await db.collection('keys').updateOne(
            { key },
            { $set: { used: true, usedAt: Date.now() } }
        );
        
        res.json({
            success: true,
            message: 'Key verified',
            expiresAt: keyDoc.expiresAt
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Health check
app.get('/', (req, res) => {
    res.json({ status: 'online', endpoints: ['/api/start', '/api/checkpoint', '/api/getkey', '/api/verify'] });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔑 Secret key: ${SECRET_KEY.substring(0, 10)}...`);
});
