import React, { useState } from 'react';
import { User, Mail, Lock, Eye, EyeOff, AlertCircle, CheckCircle } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

interface SignUpProps {
  isDarkMode?: boolean;
}

const SignUp: React.FC<SignUpProps> = ({ isDarkMode = true }) => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [validationErrors, setValidationErrors] = useState<{ [key: string]: string }>({});

  const { signUp } = useAuth();
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

    // Name validation
    if (!formData.name.trim()) {
      errors.name = 'Name is required';
    } else if (formData.name.trim().length < 2) {
      errors.name = 'Name must be at least 2 characters';
    } else if (formData.name.trim().length > 50) {
      errors.name = 'Name must not exceed 50 characters';
    } else if (!/^[a-zA-Z\s]+$/.test(formData.name.trim())) {
      errors.name = 'Name can only contain letters and spaces';
    }

    // Email validation
    if (!formData.email.trim()) {
      errors.email = 'Email is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email.trim())) {
      errors.email = 'Please provide a valid email address';
    } else if (formData.email.trim().length > 100) {
      errors.email = 'Email must not exceed 100 characters';
    }

    // Password validation
    if (!formData.password) {
      errors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      errors.password = 'Password must be at least 8 characters';
    } else if (formData.password.length > 128) {
      errors.password = 'Password must not exceed 128 characters';
    } else if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(formData.password)) {
      errors.password = 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)';
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
      const result = await signUp(formData.name.trim(), formData.email.trim(), formData.password);
      
      if (result.success) {
        setMessage({ type: 'success', text: result.message });
        // Redirect to home page after successful registration
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

      {/* Name Field */}
      <div className="space-y-2">
        <label className={`block text-sm font-medium ${
          isDarkMode ? "text-gray-300" : "text-gray-700"
        }`}>
          Full Name
        </label>
        <div className="relative">
          <User className={`absolute left-3 top-1/2 transform -translate-y-1/2 ${
            isDarkMode ? "text-gray-400" : "text-gray-500"
          }`} size={18} />
          <input
            type="text"
            name="name"
            value={formData.name}
            onChange={handleInputChange}
            placeholder="Enter your full name"
            className={`w-full pl-10 pr-4 py-3 rounded-lg border transition-all duration-300 ${
              validationErrors.name
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
        {validationErrors.name && (
          <p className={`text-sm flex items-center gap-1 ${
            isDarkMode ? "text-red-400" : "text-red-600"
          }`}>
            <AlertCircle size={14} />
            {validationErrors.name}
          </p>
        )}
      </div>

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
            placeholder="Create a strong password"
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
          <p className={`text-sm flex items-start gap-1 ${
            isDarkMode ? "text-red-400" : "text-red-600"
          }`}>
            <AlertCircle size={14} className="mt-0.5 flex-shrink-0" />
            <span>{validationErrors.password}</span>
          </p>
        )}
        
        {/* Password Requirements */}
        <div className={`text-xs space-y-1 ${
          isDarkMode ? "text-gray-400" : "text-gray-600"
        }`}>
          <p>Password must contain:</p>
          <ul className="list-disc list-inside space-y-0.5 ml-2">
            <li>At least 8 characters</li>
            <li>One uppercase letter (A-Z)</li>
            <li>One lowercase letter (a-z)</li>
            <li>One number (0-9)</li>
            <li>One special character (@$!%*?&)</li>
          </ul>
        </div>
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
        {isLoading ? 'Creating Account...' : 'Create Account'}
      </button>
    </form>
  );
};

export default SignUp;
