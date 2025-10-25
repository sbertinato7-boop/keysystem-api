// ========== WORK.INK INTEGRATION ==========
// Add these endpoints BEFORE "const PORT = ..."

// Store active sessions with their Work.ink codes
const activeSessions = new Map(); // sessionId -> { code: 'ABC123', checkpoint: 'task1' }

// Generate unique verification code for session
function generateVerificationCode() {
    return Math.random().toString(36).substring(2, 8).toUpperCase();
}

// ENDPOINT: Get Work.ink link for checkpoint
app.post('/api/get-workink-link', async (req, res) => {
    try {
        const { sessionId, signature, checkpointId } = req.body;
        
        if (!sessionId || !signature || !checkpointId) {
            return res.status(400).json({ success: false, error: 'Missing parameters' });
        }
        
        const session = await db.collection('sessions').findOne({ sessionId });
        
        if (!session) {
            return res.status(404).json({ success: false, error: 'Invalid session' });
        }
        
        // Verify signature
        if (!verifySignature({ sessionId, hwid: session.hwid, timestamp: session.timestamp }, signature)) {
            return res.status(403).json({ success: false, error: 'Invalid signature - tampering detected' });
        }
        
        // Generate unique verification code
        const verificationCode = generateVerificationCode();
        
        // Store session with code
        activeSessions.set(sessionId, {
            code: verificationCode,
            checkpoint: checkpointId,
            hwid: session.hwid,
            createdAt: Date.now()
        });
        
        // Clean up old sessions (older than 10 minutes)
        for (const [sid, data] of activeSessions.entries()) {
            if (Date.now() - data.createdAt > 600000) {
                activeSessions.delete(sid);
            }
        }
        
        // Return Work.ink link based on checkpoint
        let workinkUrl;
        if (checkpointId === 'task1') {
            workinkUrl = 'https://workink.net/24Hy/aivwflop';
        } else if (checkpointId === 'task2') {
            workinkUrl = 'https://workink.net/24Hy/l3vn0tbt';
        } else {
            return res.status(400).json({ success: false, error: 'Invalid checkpoint' });
        }
        
        res.json({
            success: true,
            link: workinkUrl,
            verificationCode: verificationCode,
            message: 'Complete the Work.ink task, then return and enter your code'
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ENDPOINT: Verify checkpoint completion with code
app.post('/api/verify-checkpoint-code', async (req, res) => {
    try {
        const { sessionId, code } = req.body;
        
        if (!sessionId || !code) {
            return res.status(400).json({ success: false, error: 'Missing parameters' });
        }
        
        const session = await db.collection('sessions').findOne({ sessionId });
        
        if (!session) {
            return res.status(404).json({ success: false, error: 'Invalid session' });
        }
        
        // Get stored verification data
        const verificationData = activeSessions.get(sessionId);
        
        if (!verificationData) {
            return res.status(404).json({ success: false, error: 'No pending verification. Please click the checkpoint button again.' });
        }
        
        // Verify code matches
        if (verificationData.code.toUpperCase() !== code.toUpperCase()) {
            return res.status(403).json({ success: false, error: 'Invalid verification code' });
        }
        
        // Check if already completed
        const completedIds = session.checkpoints.map(cp => cp.id);
        if (completedIds.includes(verificationData.checkpoint)) {
            return res.json({ success: true, message: 'Checkpoint already completed' });
        }
        
        // Mark checkpoint as complete
        await db.collection('sessions').updateOne(
            { sessionId },
            { 
                $push: { 
                    checkpoints: { 
                        id: verificationData.checkpoint, 
                        completedAt: Date.now(),
                        verified: true 
                    } 
                } 
            }
        );
        
        // Remove from active sessions
        activeSessions.delete(sessionId);
        
        // Generate new signature
        const newSignature = signData({ sessionId, hwid: session.hwid, timestamp: session.timestamp });
        
        res.json({
            success: true,
            message: `Checkpoint ${verificationData.checkpoint} completed!`,
            signature: newSignature
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// VERIFICATION PAGE: Checkpoint 1 (Where Work.ink redirects users)
app.get('/verify-checkpoint1', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Checkpoint 1 Complete</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { color: #667eea; margin-bottom: 20px; font-size: 32px; }
        .checkmark {
            width: 80px;
            height: 80px;
            background: #4caf50;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 30px;
            font-size: 48px;
            color: white;
        }
        p { color: #666; font-size: 16px; line-height: 1.6; margin-bottom: 30px; }
        .btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 15px 40px;
            border-radius: 10px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover { background: #5568d3; }
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">✓</div>
        <h1>Checkpoint 1 Complete!</h1>
        <p>You can now close this page and return to the key system to continue.</p>
        <a href="${process.env.FRONTEND_URL || 'about:blank'}" class="btn">Return to Key System</a>
    </div>
    <script>
        // Try to close window after 5 seconds
        setTimeout(() => {
            window.close();
        }, 5000);
    </script>
</body>
</html>
    `);
});

// VERIFICATION PAGE: Checkpoint 2
app.get('/verify-checkpoint2', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Checkpoint 2 Complete</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { color: #667eea; margin-bottom: 20px; font-size: 32px; }
        .checkmark {
            width: 80px;
            height: 80px;
            background: #4caf50;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 30px;
            font-size: 48px;
            color: white;
        }
        p { color: #666; font-size: 16px; line-height: 1.6; margin-bottom: 30px; }
        .btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 15px 40px;
            border-radius: 10px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover { background: #5568d3; }
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">✓</div>
        <h1>Checkpoint 2 Complete!</h1>
        <p>You can now close this page and return to the key system to get your final key.</p>
        <a href="${process.env.FRONTEND_URL || 'about:blank'}" class="btn">Return to Key System</a>
    </div>
    <script>
        setTimeout(() => {
            window.close();
        }, 5000);
    </script>
</body>
</html>
    `);
});
