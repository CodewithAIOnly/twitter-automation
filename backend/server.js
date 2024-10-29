const express = require('express');
const cors = require('cors');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const axios = require('axios');
const rateLimit = require('express-rate-limit');

const crypto = require('crypto');
const User = require('./models/User');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Could not connect to MongoDB', err));

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ success: false, error: 'No token provided' });

  jwt.verify(token.split(' ')[1], process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ success: false, error: 'Failed to authenticate token' });
    req.userId = decoded.id;
    next();
  });
};

// Rate limiting middleware
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // 5 requests per minute
  message: { success: false, error: 'Rate limit exceeded. Please try again later.' }
});

// User registration endpoint
app.post('/api/users/signup', async (req, res) => {
  console.log('Received signup request:', req.body);
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      console.log('Missing email or password');
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('User already exists:', email);
      return res.status(400).json({ success: false, message: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    console.log('User registered successfully:', email);
    res.json({ success: true, message: 'User registered successfully' });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, message: 'Server error', error: error.message });
  }
});

// User login endpoint
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ success: true, token, user: { id: user._id, email: user.email } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error', error: error.message });
  }
});

// Helper function to generate AI reply for posts
async function generateLongAIReply(prompt) {
  return retryWithExponentialBackoff(async () => {
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: "gemini-pro" });
    const result = await model.generateContent(prompt);
    let reply = result.response.text().trim();
    
    // Ensure we have 5-6 sentences
    const sentences = reply.match(/[^\.!\?]+[\.!\?]+/g) || [];
    if (sentences.length < 5) {
      // If we have fewer than 5 sentences, generate additional content
      const additionalPrompt = `Add ${5 - sentences.length} more sentences to complete this Twitter post:\n\n${reply}`;
      const additionalResult = await model.generateContent(additionalPrompt);
      const additionalReply = additionalResult.response.text().trim();
      reply += ' ' + additionalReply;
    }
    
    // Re-split into sentences and limit to 6
    const finalSentences = reply.match(/[^\.!\?]+[\.!\?]+/g) || [];
    return finalSentences.slice(0, 6).join(' ');
  });
}

async function handleXReply(text, previousMessages, additionalContext) {
  let prompt = `Generate a concise and engaging X (formerly Twitter) ${previousMessages === 'tweet' ? 'tweet' : 'reply'} based on the following: "${previousMessages}"`;
  return await generateGeminiResponse(prompt);
}

app.post('/api/get-ai-reply', verifyToken, apiLimiter, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Check daily limit
    const today = new Date().setHours(0, 0, 0, 0);
    if (user.lastRequestDate.setHours(0, 0, 0, 0) < today) {
      user.dailyRequestCount = 0;
      user.lastRequestDate = new Date();
    }

    if (user.dailyRequestCount >= 100) {
      return res.status(429).json({ success: false, error: 'Daily request limit exceeded. Please try again tomorrow.' });
    }

    const { prompt, text, context, previousMessages, additionalContext } = req.body;

    let reply;
    switch (context) {
      case 'tweet':
      case 'reply':
        console.log(`${context.charAt(0).toUpperCase() + context.slice(1)} context:`, JSON.stringify(previousMessages, null, 2));
        reply = await handleXReply(text, previousMessages, additionalContext);
        break;
      case 'message':
        console.log('Message context:', JSON.stringify(previousMessages, null, 2));
        reply = await handleXMessage(prompt, text, previousMessages, additionalContext);
        break;
      default:
        throw new Error('Invalid context');
    }

    // Increment daily request count
    user.dailyRequestCount += 1;
    await user.save();

    res.json({ success: true, reply });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message || 'An error occurred while generating the reply' });
  }
});

async function handleXMessage(prompt, text, previousMessages, additionalContext) {
  let prompts = `Generate a friendly and appropriate direct message reply to: "${prompt}  ${text}".`;
  return await generateGeminiResponse(prompts);
}

async function generateGeminiResponse(prompt) {
  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  const model = genAI.getGenerativeModel({ model: "gemini-pro" });

  const result = await model.generateContent({
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: {
      temperature: 0.7,
      topK: 40,
      topP: 0.95,
      maxOutputTokens: 1024,
    },
    safetySettings: [
      {
        category: "HARM_CATEGORY_HARASSMENT",
        threshold: "BLOCK_MEDIUM_AND_ABOVE"
      },
      {
        category: "HARM_CATEGORY_HATE_SPEECH",
        threshold: "BLOCK_MEDIUM_AND_ABOVE"
      },
      {
        category: "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        threshold: "BLOCK_MEDIUM_AND_ABOVE"
      },
      {
        category: "HARM_CATEGORY_DANGEROUS_CONTENT",
        threshold: "BLOCK_MEDIUM_AND_ABOVE"
      },
    ],
  });

  const response = result.response;
  return response.text();
}

// Function to handle retries
async function retryWithExponentialBackoff(fn, maxRetries = 3, initialDelay = 1000) {
  let retries = 0;
  while (retries < maxRetries) {
    try {
      return await fn();
    } catch (error) {
      if (error.status !== 500 || retries === maxRetries - 1) {
        throw error;
      }
      retries++;
      const delay = initialDelay * Math.pow(2, retries);
      console.log(`Retrying after ${delay}ms...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// Update the generateShortAIReply function to use retries
async function generateShortAIReply(prompt) {
  return retryWithExponentialBackoff(async () => {
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: "gemini-pro" });
    
    const result = await model.generateContent(prompt);
    let reply = result.response.text().trim();
    reply = reply.replace(/[^\w\s]|_/g, "").replace(/\s+/g, " ");
    const words = reply.split(/\s+/);
    return words.slice(0, 20).join(' ');
  });
}

// Twitter OAuth 2.0 endpoints
app.get('/api/twitter/auth', verifyToken, async (req, res) => {
  try {
    const codeVerifier = crypto.randomBytes(32).toString('hex');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    // Store the code verifier in the user's session or database
    await User.findByIdAndUpdate(req.userId, { twitterCodeVerifier: codeVerifier });

    const authUrl = `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${process.env.TWITTER_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.TWITTER_CALLBACK_URL)}&scope=tweet.read%20tweet.write%20users.read&state=${req.userId}&code_challenge=${codeChallenge}&code_challenge_method=S256`;

    res.json({ authUrl });
  } catch (error) {
    console.error('Twitter OAuth Error:', error);
    res.status(500).json({ error: 'Failed to initiate Twitter authentication' });
  }
});

app.get('/api/twitter/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state) {
    return res.redirect('https://twitter.com?error=Authentication failed');
  }

  try {
    const user = await User.findById(state);
    if (!user || !user.twitterCodeVerifier) {
      throw new Error('Invalid state or code verifier not found');
    }

    const tokenResponse = await axios.post('https://api.twitter.com/2/oauth2/token', 
      new URLSearchParams({
        code,
        grant_type: 'authorization_code',
        client_id: process.env.TWITTER_CLIENT_ID,
        redirect_uri: process.env.TWITTER_CALLBACK_URL,
        code_verifier: user.twitterCodeVerifier
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${Buffer.from(`${process.env.TWITTER_CLIENT_ID}:${process.env.TWITTER_CLIENT_SECRET}`).toString('base64')}`
        }
      }
    );

    const { access_token, refresh_token, expires_in } = tokenResponse.data;

    // Update user in database with Twitter tokens
    await User.findByIdAndUpdate(state, {
      twitterAccessToken: access_token,
      twitterRefreshToken: refresh_token,
      twitterTokenExpiresAt: new Date(Date.now() + expires_in * 1000),
      twitterCodeVerifier: null // Clear the code verifier
    });

    res.redirect('https://twitter.com?twitter=connected');
  } catch (error) {
    console.error('Twitter OAuth Error:', error.response ? error.response.data : error.message);
    res.redirect(`https://twitter.com?error=${encodeURIComponent('Failed to connect Twitter account')}`);
  }
});

app.get('/api/twitter/user-info', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user || !user.twitterAccessToken) {
      return res.status(400).json({ success: false, error: 'Twitter access token not found' });
    }

    const response = await axios.get('https://api.twitter.com/2/users/me', {
      headers: { 'Authorization': `Bearer ${user.twitterAccessToken}` }
    });

    res.json({ success: true, profile: response.data.data });
  } catch (error) {
    console.error('Twitter API Error:', error.response ? error.response.data : error.message);
    if (error.response && error.response.status === 401) {
      return res.status(401).json({ success: false, error: 'Twitter token expired', requiresReauth: true });
    }
    res.status(500).json({ success: false, error: 'Failed to fetch Twitter profile', details: error.message });
  }
});

// Twitter tweet endpoint
app.post('/api/twitter/tweet', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user || !user.twitterAccessToken) {
      return res.status(400).json({ success: false, error: 'Twitter access token not found' });
    }

    const { text } = req.body;

    const response = await axios.post('https://api.twitter.com/2/tweets', 
      { text },
      {
        headers: { 'Authorization': `Bearer ${user.twitterAccessToken}` }
      }
    );

    res.json({ success: true, message: 'Tweet posted successfully', data: response.data });
  } catch (error) {
    console.error('Twitter Tweet Error:', error.response ? error.response.data : error.message);
    if (error.response && error.response.status === 401) {
      return  res.status(401).json({ success: false, error: 'Twitter token expired', requiresReauth: true });
    }
    res.status(500).json({ success: false, error: 'Failed to post tweet', details: error.message });
  }
});

// Refresh Twitter access token
async function refreshTwitterToken(user) {
  try {
    const tokenResponse = await axios.post('https://api.twitter.com/2/oauth2/token', 
      new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: user.twitterRefreshToken,
        client_id: process.env.TWITTER_CLIENT_ID
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${Buffer.from(`${process.env.TWITTER_CLIENT_ID}:${process.env.TWITTER_CLIENT_SECRET}`).toString('base64')}`
        }
      }
    );

    const { access_token, refresh_token, expires_in } = tokenResponse.data;

    // Update user in database with new Twitter tokens
    await User.findByIdAndUpdate(user._id, {
      twitterAccessToken: access_token,
      twitterRefreshToken: refresh_token,
      twitterTokenExpiresAt: new Date(Date.now() + expires_in * 1000)
    });

    return access_token;
  } catch (error) {
    console.error('Failed to refresh Twitter token:', error);
    throw error;
  }
}

app.post('/api/generate', verifyToken, apiLimiter, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Check daily limit
    const today = new Date().setHours(0, 0, 0, 0);
    if (user.lastRequestDate.setHours(0, 0, 0, 0) < today) {
      user.dailyRequestCount = 0;
      user.lastRequestDate = new Date();
    }

    if (user.dailyRequestCount >= 100) {
      return res.status(429).json({ success: false, error: 'Daily request limit exceeded. Please try again tomorrow.' });
    }

    const { prompt } = req.body;
    const apiKey = process.env.GEMINI_API_KEY;

    console.log("Using Gemini API key:", apiKey);

    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: "gemini-pro" });

    const result = await model.generateContent({
      contents: [{ parts: [{ text: prompt }] }]
    });

    if (!result.response) {
      throw new Error('No response from Gemini API');
    }

    const generatedText = result.response.text();
    console.log("API response data:", { generatedText });

    // Increment daily request count
    user.dailyRequestCount += 1;
    await user.save();

    res.json({ generatedText });
  } catch (error) {
    console.error("Error generating text:", error);
    res.status(500).json({ error: error.message });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});