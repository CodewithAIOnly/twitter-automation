const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true, 
    unique: true 
  },
  password: { 
    type: String, 
    required: true 
  },
  geminiApiKey: { 
    type: String, 
    required: false 
  },
  twitterAccessToken: { 
    type: String, 
    required: false 
  },
  twitterRefreshToken: { 
    type: String, 
    required: false 
  },
  twitterTokenExpiresAt: { 
    type: Date, 
    required: false 
  },
  twitterCodeVerifier: { 
    type: String, 
    required: false 
  },
  twitterId: { 
    type: String, 
    required: false 
  },
  twitterScreenName: { 
    type: String, 
    required: false 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  lastLogin: { 
    type: Date, 
    required: false 
  },

  dailyRequestCount: { 
    type: Number, default: 0 
  },
  lastRequestDate: { 
    type: Date, default: Date.now 
  }
  
});

// Add a method to check if the Twitter token is expired
userSchema.methods.isTwitterTokenExpired = function() {
  return this.twitterTokenExpiresAt && this.twitterTokenExpiresAt < new Date();
};

const User = mongoose.model('User', userSchema);

module.exports = User;