"use strict";

const express = require('express');
const bodyParser = require('body-parser');
const { Keychain } = require('./password-manager');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware - API routes must come before static files
app.use(bodyParser.json());

// In-memory session storage (for demo purposes)
let activeKeychain = null;
let masterPassword = null;

// Create passwords folder if it doesn't exist
const PASSWORDS_DIR = path.join(__dirname, 'passwords');
if (!fs.existsSync(PASSWORDS_DIR)) {
  fs.mkdirSync(PASSWORDS_DIR);
}

// Helper function to save password entry to file
async function savePasswordToFile(domainName, domainHash, iv, ciphertext) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `${timestamp}.txt`;
  const filepath = path.join(PASSWORDS_DIR, filename);
  
  const content = `PASSWORD ENTRY
Domain Name: ${domainName}
Saved At: ${new Date().toISOString()}
HASHED DOMAIN (SHA-256): ${domainHash}
INITIALIZATION VECTOR (IV): ${iv}
ENCRYPTED PASSWORD (AES-GCM): ${ciphertext}
`;

  fs.writeFileSync(filepath, content.trim());
  console.log(`✅ Password saved to: ${filename}`);
  return filename;
}

// Initialize new keychain
app.post('/api/init', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }
    activeKeychain = await Keychain.init(password);
    masterPassword = password;
    res.json({ success: true, message: 'Keychain initialized' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Load existing keychain
app.post('/api/load', async (req, res) => {
  try {
    const { password, data, checksum } = req.body;
    if (!password || !data) {
      return res.status(400).json({ error: 'Password and data are required' });
    }
    activeKeychain = await Keychain.load(password, data, checksum);
    masterPassword = password;
    res.json({ success: true, message: 'Keychain loaded' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Dump keychain
app.get('/api/dump', async (req, res) => {
  try {
    if (!activeKeychain) {
      return res.status(400).json({ error: 'No active keychain' });
    }
    const [data, checksum] = await activeKeychain.dump();
    res.json({ data, checksum });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get password
app.post('/api/get', async (req, res) => {
  try {
    if (!activeKeychain) {
      return res.status(400).json({ error: 'No active keychain' });
    }
    const { name } = req.body;
    const password = await activeKeychain.get(name);
    res.json({ password });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Set password
app.post('/api/set', async (req, res) => {
  try {
    if (!activeKeychain) {
      return res.status(400).json({ error: 'No active keychain' });
    }
    const { name, password } = req.body;
    console.log(`Setting password for: ${name}`);
    await activeKeychain.set(name, password);
    
    // Save to file with timestamp
    const [data, checksum] = await activeKeychain.dump();
    const parsed = JSON.parse(data);
    const nameHash = await activeKeychain._hashName(name);
    console.log(`Name hash: ${nameHash}`);
    console.log(`KVS keys:`, Object.keys(parsed.kvs));
    const entry = parsed.kvs[nameHash];
    console.log(`Entry found:`, !!entry);
    
    if (entry) {
      const filename = await savePasswordToFile(name, nameHash, entry.iv, entry.ciphertext);
      res.json({ 
        success: true, 
        message: 'Password saved',
        file: filename 
      });
    } else {
      console.log('Entry not found in kvs!');
      res.json({ success: true, message: 'Password saved but file not created' });
    }
  } catch (error) {
    console.error('Error in /api/set:', error);
    res.status(500).json({ error: error.message });
  }
});

// Remove password
app.post('/api/remove', async (req, res) => {
  try {
    if (!activeKeychain) {
      return res.status(400).json({ error: 'No active keychain' });
    }
    const { name } = req.body;
    const removed = await activeKeychain.remove(name);
    res.json({ success: removed, message: removed ? 'Password removed' : 'Password not found' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Check if keychain is active
app.get('/api/status', (req, res) => {
  res.json({ active: !!activeKeychain });
});

// Logout / Reset keychain
app.post('/api/logout', (req, res) => {
  console.log('Logout request received');
  activeKeychain = null;
  masterPassword = null;
  console.log('Keychain cleared');
  res.status(200).json({ success: true, message: 'Keychain cleared' });
});

// Change master password
app.post('/api/change-password', async (req, res) => {
  try {
    if (!activeKeychain) {
      return res.status(400).json({ error: 'No active keychain' });
    }
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Both current and new passwords are required' });
    }

    // Verify current password matches
    if (currentPassword !== masterPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Export current keychain data
    const [data, checksum] = await activeKeychain.dump();

    // Create new keychain with new password and same data
    activeKeychain = await Keychain.load(newPassword, data, checksum);
    masterPassword = newPassword;

    res.json({ success: true, message: 'Master password changed successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Serve static files AFTER API routes
app.use(express.static('public'));

app.listen(PORT, () => {
  console.log(`Password Manager server running at http://localhost:${PORT}`);
  console.log(`Password files will be saved to: ${PASSWORDS_DIR}`);
  console.log(`Each password creates a file named: [timestamp].txt`);
});
