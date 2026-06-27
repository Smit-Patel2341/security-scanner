require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const client = new Anthropic.default({ apiKey: process.env.ANTHROPIC_API_KEY });

app.post('/scan', async (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ error: 'No code provided' });
  }

  try {
    const message = await client.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      messages: [
        {
          role: 'user',
          content: `You are a senior cybersecurity expert. Analyze the following code for security vulnerabilities.

For each vulnerability found, provide:
1. Vulnerability name
2. Severity (Critical / High / Medium / Low)
3. Line or area of code affected
4. Why it is dangerous
5. How to fix it

Format your response as JSON like this:
{
  "vulnerabilities": [
    {
      "name": "SQL Injection",
      "severity": "Critical",
      "location": "line 5",
      "description": "why it is dangerous",
      "fix": "how to fix it"
    }
  ],
  "summary": "overall summary here"
}

Here is the code to analyze:
\`\`\`
${code}
\`\`\``,
        },
      ],
    });

    const responseText = message.content[0].text;
    const jsonMatch = responseText.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const result = JSON.parse(jsonMatch[0]);
      res.json(result);
    } else {
      res.json({ summary: responseText, vulnerabilities: [] });
    }
  } catch (error) {
    console.error('Full error:', JSON.stringify(error, null, 2), error.message, error.status);
    res.status(500).json({ error: 'Something went wrong. Check your API key.' });
  }
});

app.listen(3000, () => {
  console.log('Security scanner running at http://localhost:3000');
});