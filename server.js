require('dotenv').config();
const express = require('express');
const cors = require('cors');
const OpenAI = require('openai');

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static('.'));

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Simple in-memory rate limiter: max 20 requests per IP per 15 minutes
const rateLimitMap = new Map();
const RATE_LIMIT = 20;
const RATE_WINDOW_MS = 15 * 60 * 1000;

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count >= RATE_LIMIT) return false;
  entry.count++;
  return true;
}

// Clean up stale entries every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    if (now - entry.windowStart > RATE_WINDOW_MS) rateLimitMap.delete(ip);
  }
}, 30 * 60 * 1000);

app.post('/scan', async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests. Please wait 15 minutes before scanning again.' });
  }

  const { code, language } = req.body;

  if (!code) {
    return res.status(400).json({ error: 'No code provided.' });
  }

  if (code.length > 50000) {
    return res.status(413).json({ error: 'Code is too large. Please limit to 50,000 characters.' });
  }

  const langContext = language && language !== 'auto' ? `The code is written in ${language}.` : '';

  const prompt = `You are a senior cybersecurity expert specializing in secure code review. Analyze the following code for security vulnerabilities.

${langContext}

For each vulnerability found, provide:
1. Vulnerability name
2. Severity: exactly one of Critical / High / Medium / Low
3. Location (line number or function/area name)
4. CWE ID if applicable (e.g. CWE-89)
5. OWASP Top 10 category if applicable (e.g. A03:2021 – Injection)
6. Why it is dangerous
7. A concrete fix with example code where possible

Respond ONLY with valid JSON in this exact format (no markdown, no extra text):
{
  "vulnerabilities": [
    {
      "name": "SQL Injection",
      "severity": "Critical",
      "location": "line 5 – getUserById()",
      "cweId": "CWE-89",
      "owasp": "A03:2021 – Injection",
      "description": "why it is dangerous",
      "fix": "how to fix it with example"
    }
  ],
  "summary": "overall summary here"
}

If no vulnerabilities are found, return an empty vulnerabilities array with a summary explaining the code looks secure.

Code to analyze:
\`\`\`
${code}
\`\`\``;

  try {
    const message = await client.chat.completions.create({
      model: 'gpt-4o',
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }],
    });

    const responseText = message.choices[0].message.content;

    // Strip markdown code fences if present, then extract JSON
    const stripped = responseText.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '');
    const jsonMatch = stripped.match(/\{[\s\S]*\}/);

    if (jsonMatch) {
      try {
        const result = JSON.parse(jsonMatch[0]);
        return res.json(result);
      } catch {
        // JSON malformed — fall through to plain text response
      }
    }

    res.json({ summary: responseText, vulnerabilities: [] });
  } catch (error) {
    console.error('Scan error:', error.message, error.status);
    if (error.status === 401) {
      return res.status(500).json({ error: 'Invalid API key. Check your OPENAI_API_KEY in .env.' });
    }
    res.status(500).json({ error: 'Analysis failed. Please try again.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Security scanner running at http://localhost:${PORT}`);
});
