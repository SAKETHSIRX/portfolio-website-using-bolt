import React, { useState, useEffect } from 'react';
import { ArrowLeft } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import SignIn from './signin';
import SignUp from './signup';

interface AuthPageProps {
  isDarkMode?: boolean;
}

const AuthPage: React.FC<AuthPageProps> = ({ isDarkMode: propIsDarkMode }) => {
  const [isSignIn, setIsSignIn] = useState(true);
  const [isDarkMode, setIsDarkMode] = useState(propIsDarkMode ?? true);
  const navigate = useNavigate();

  // Initialize theme from localStorage or system preference
  useEffect(() => {
    if (propIsDarkMode === undefined) {
      const savedTheme = localStorage.getItem('theme');
      if (savedTheme) {
        setIsDarkMode(savedTheme === 'dark');
      } else {
        // Check system preference
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        setIsDarkMode(prefersDark);
      }
    }
  }, [propIsDarkMode]);

  const handleGoBack = () => {
    navigate('/');
  };

  return (
    <div className={`min-h-screen flex items-center justify-center relative overflow-hidden ${
      isDarkMode ? "bg-black text-white" : "bg-white text-black"
    }`}>
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-5">
        <div className="absolute inset-0" style={{
          backgroundImage: `radial-gradient(circle at 1px 1px, ${isDarkMode ? 'white' : 'black'} 1px, transparent 0)`,
          backgroundSize: '20px 20px'
        }} />
      </div>

      {/* Back Button */}
      <button
        onClick={handleGoBack}
        className={`absolute top-6 left-6 flex items-center gap-2 px-4 py-2 rounded-lg transition-all duration-300 backdrop-blur-sm border ${
          isDarkMode 
            ? "bg-white/10 hover:bg-white/20 border-white/20 text-white hover:border-white/30" 
            : "bg-black/10 hover:bg-black/20 border-black/20 text-black hover:border-black/30"
        }`}
      >
        <ArrowLeft size={18} />
        Back to Home
      </button>

      {/* Auth Container */}
      <div className="relative z-10 w-full max-w-md mx-auto px-6">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className={`text-3xl font-bold mb-2 ${
            isDarkMode ? "text-white" : "text-black"
          }`}>
            Welcome to sakethsirx
          </h1>
          <p className={`${
            isDarkMode ? "text-gray-400" : "text-gray-600"
          }`}>
            {isSignIn ? "Sign in to your account" : "Create your account"}
          </p>
        </div>

        {/* Auth Form Container */}
        <div className={`backdrop-blur-md rounded-2xl border p-8 ${
          isDarkMode 
            ? "bg-white/5 border-white/10" 
            : "bg-black/5 border-black/10"
        }`}>
          {/* Toggle Buttons */}
          <div className={`flex rounded-lg p-1 mb-6 ${
            isDarkMode ? "bg-white/10" : "bg-black/10"
          }`}>
            <button
              onClick={() => setIsSignIn(true)}
              className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-all duration-300 ${
                isSignIn
                  ? isDarkMode 
                    ? "bg-white text-black" 
                    : "bg-black text-white"
                  : isDarkMode 
                    ? "text-gray-400 hover:text-white" 
                    : "text-gray-600 hover:text-black"
              }`}
            >
              Sign In
            </button>
            <button
              onClick={() => setIsSignIn(false)}
              className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-all duration-300 ${
                !isSignIn
                  ? isDarkMode 
                    ? "bg-white text-black" 
                    : "bg-black text-white"
                  : isDarkMode 
                    ? "text-gray-400 hover:text-white" 
                    : "text-gray-600 hover:text-black"
              }`}
            >
              Sign Up
            </button>
          </div>

          {/* Auth Forms */}
          {isSignIn ? (
            <SignIn isDarkMode={isDarkMode} />
          ) : (
            <SignUp isDarkMode={isDarkMode} />
          )}
        </div>

        {/* Footer */}
        <div className="text-center mt-6">
          <p className={`text-sm ${
            isDarkMode ? "text-gray-500" : "text-gray-500"
          }`}>
            By continuing, you agree to our Terms of Service and Privacy Policy
          </p>
        </div>
      </div>
    </div>
  );
};

export default AuthPage;