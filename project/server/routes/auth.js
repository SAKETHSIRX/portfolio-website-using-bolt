import express from 'express';
import rateLimit from 'express-rate-limit';
import {
  signUp,
  signIn,
  getProfile,
  updateProfile,
  changePassword,
  signOut
} from '../controllers/authController.js';
import {
  validateSignUp,
  validateSignIn,
  validateUpdateProfile,
  validateChangePassword
} from '../middleware/validation.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Public routes (with rate limiting)
router.post('/signup', authLimiter, validateSignUp, signUp);
router.post('/signin', authLimiter, validateSignIn, signIn);

// Protected routes (require authentication)
router.get('/profile', generalLimiter, authenticateToken, getProfile);
router.put('/profile', generalLimiter, authenticateToken, validateUpdateProfile, updateProfile);
router.put('/change-password', generalLimiter, authenticateToken, validateChangePassword, changePassword);
router.post('/signout', generalLimiter, authenticateToken, signOut);

// Health check endpoint
router.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Auth service is running',
    timestamp: new Date().toISOString()
  });
});

export default router;