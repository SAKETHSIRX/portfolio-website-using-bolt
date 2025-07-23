import React, { useState } from 'react';
import { Mail, Lock, Eye, EyeOff, AlertCircle, CheckCircle } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

interface SignInProps {
  isDarkMode?: boolean;
}

const SignIn: React.FC<SignInProps> = ({ isDarkMode = true }) => {
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [validationErrors, setValidationErrors] = useState<{ [key: string]: string }>({});

  const { signIn } = useAuth();
  const navigate = useNavigate();

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    // Clear validation error for this field
    if (validationErrors[name]) {
      setValidationErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const validateForm = () => {
    const errors: { [key: string]: string } = {};

    // Email validation
    if (!formData.email.trim()) {
      errors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email.trim())) {
      errors.email = 'Please provide a valid email address';
    }

    // Password validation
    if (!formData.password) {
      errors.password = 'Password is required';
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setIsLoading(true);
    setMessage(null);

    try {
      const result = await signIn(formData.email.trim(), formData.password);
      
      if (result.success) {
        setMessage({ type: 'success', text: result.message });
        // Redirect to home page after successful sign in
        setTimeout(() => {
          navigate('/');
        }, 1500);
      } else {
        setMessage({ type: 'error', text: result.message });
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'An unexpected error occurred. Please try again.' });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Message Display */}
      {message && (
        <div className={`flex items-center gap-2 p-3 rounded-lg ${
          message.type === 'success'
            ? isDarkMode 
              ? "bg-green-500/10 border border-green-500/20 text-green-400"
              : "bg-green-50 border border-green-200 text-green-600"
            : isDarkMode 
              ? "bg-red-500/10 border border-red-500/20 text-red-400"
              : "bg-red-50 border border-red-200 text-red-600"
        }`}>
          {message.type === 'success' ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
          <span className="text-sm">{message.text}</span>
        </div>
      )}

      {/* Email Field */}
      <div className="space-y-2">
        <label className={`block text-sm font-medium ${
          isDarkMode ? "text-gray-300" : "text-gray-700"
        }`}>
          Email Address
        </label>
        <div className="relative">
          <Mail className={`absolute left-3 top-1/2 transform -translate-y-1/2 ${
            isDarkMode ? "text-gray-400" : "text-gray-500"
          }`} size={18} />
          <input
            type="email"
            name="email"
            value={formData.email}
            onChange={handleInputChange}
            placeholder="Enter your email"
            className={`w-full pl-10 pr-4 py-3 rounded-lg border transition-all duration-300 ${
              validationErrors.email
                ? isDarkMode 
                  ? "bg-red-500/10 border-red-500/50 text-white placeholder-red-300"
                  : "bg-red-50 border-red-300 text-black placeholder-red-400"
                : isDarkMode 
                  ? "bg-white/10 border-white/20 text-white placeholder-gray-400 focus:border-white/40 focus:bg-white/15"
                  : "bg-black/5 border-black/20 text-black placeholder-gray-500 focus:border-black/40 focus:bg-black/10"
            }`}
            disabled={isLoading}
          />
        </div>
        {validationErrors.email && (
          <p className={`text-sm flex items-center gap-1 ${
            isDarkMode ? "text-red-400" : "text-red-600"
          }`}>
            <AlertCircle size={14} />
            {validationErrors.email}
          </p>
        )}
      </div>

      {/* Password Field */}
      <div className="space-y-2">
        <label className={`block text-sm font-medium ${
          isDarkMode ? "text-gray-300" : "text-gray-700"
        }`}>
          Password
        </label>
        <div className="relative">
          <Lock className={`absolute left-3 top-1/2 transform -translate-y-1/2 ${
            isDarkMode ? "text-gray-400" : "text-gray-500"
          }`} size={18} />
          <input
            type={showPassword ? "text" : "password"}
            name="password"
            value={formData.password}
            onChange={handleInputChange}
            placeholder="Enter your password"
            className={`w-full pl-10 pr-12 py-3 rounded-lg border transition-all duration-300 ${
              validationErrors.password
                ? isDarkMode 
                  ? "bg-red-500/10 border-red-500/50 text-white placeholder-red-300"
                  : "bg-red-50 border-red-300 text-black placeholder-red-400"
                : isDarkMode 
                  ? "bg-white/10 border-white/20 text-white placeholder-gray-400 focus:border-white/40 focus:bg-white/15"
                  : "bg-black/5 border-black/20 text-black placeholder-gray-500 focus:border-black/40 focus:bg-black/10"
            }`}
            disabled={isLoading}
          />
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className={`absolute right-3 top-1/2 transform -translate-y-1/2 ${
              isDarkMode ? "text-gray-400 hover:text-white" : "text-gray-500 hover:text-black"
            }`}
            disabled={isLoading}
          >
            {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
          </button>
        </div>
        {validationErrors.password && (
          <p className={`text-sm flex items-center gap-1 ${
            isDarkMode ? "text-red-400" : "text-red-600"
          }`}>
            <AlertCircle size={14} />
            {validationErrors.password}
          </p>
        )}
      </div>

      {/* Submit Button */}
      <button
        type="submit"
        disabled={isLoading}
        className={`w-full py-3 px-4 rounded-lg font-medium transition-all duration-300 ${
          isLoading
            ? isDarkMode 
              ? "bg-gray-600 text-gray-400 cursor-not-allowed"
              : "bg-gray-300 text-gray-500 cursor-not-allowed"
            : isDarkMode 
              ? "bg-white text-black hover:bg-gray-100 active:bg-gray-200"
              : "bg-black text-white hover:bg-gray-800 active:bg-gray-900"
        }`}
      >
        {isLoading ? 'Signing In...' : 'Sign In'}
      </button>

      {/* Forgot Password Link */}
      <div className="text-center">
        <button
          type="button"
          className={`text-sm transition-colors duration-300 ${
            isDarkMode 
              ? "text-gray-400 hover:text-white" 
              : "text-gray-600 hover:text-black"
          }`}
          disabled={isLoading}
        >
          Forgot your password?
        </button>
      </div>
    </form>
  );
};

export default SignIn;
