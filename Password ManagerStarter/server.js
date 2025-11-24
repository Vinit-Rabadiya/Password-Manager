"use strict";

const express = require('express');
const bodyParser = require('body-parser');
const { Keychain } = require('./password-manager');

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());
app.use(express.static('public'));

// In-memory session storage (for demo purposes)
let activeKeychain = null;
let masterPassword = null;

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
    await activeKeychain.set(name, password);
    res.json({ success: true, message: 'Password saved' });
  } catch (error) {
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

app.listen(PORT, () => {
  console.log(`Password Manager server running at http://localhost:${PORT}`);
});
