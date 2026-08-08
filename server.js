// Local development server.
// In production, Vercel serves index.html statically and runs api/scan.js as a
// serverless function. This file reuses that same handler so `node server.js`
// gives an identical experience on http://localhost:3000.
require('dotenv').config();
const express = require('express');
const scan = require('./api/scan');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static('.'));

app.post('/api/scan', (req, res) => scan(req, res));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Security scanner (local dev) running on http://localhost:${PORT}`);
});
