import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { authAPI, User } from '../services/api';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  signIn: (email: string, password: string) => Promise<{ success: boolean; message: string }>;
  signUp: (name: string, email: string, password: string) => Promise<{ success: boolean; message: string }>;
  signOut: () => Promise<void>;
  updateProfile: (updates: { name?: string; email?: string }) => Promise<{ success: boolean; message: string }>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Initialize auth state on app load
  useEffect(() => {
    initializeAuth();
  }, []);

  const initializeAuth = async () => {
    try {
      if (authAPI.isAuthenticated()) {
        const currentUser = authAPI.getCurrentUser();
        if (currentUser) {
          setUser(currentUser);
          
          // Verify token is still valid by fetching fresh user data
          try {
            const response = await authAPI.getProfile();
            if (response.success && response.data) {
              setUser(response.data.user);
            } else {
              // Token is invalid, clear auth
              await signOut();
            }
          } catch (error) {
            // Token is invalid, clear auth
            await signOut();
          }
        }
      }
    } catch (error) {
      console.error('Auth initialization error:', error);
      await signOut();
    } finally {
      setIsLoading(false);
    }
  };

  const signIn = async (email: string, password: string) => {
    try {
      const response = await authAPI.signIn({ email, password });
      
      if (response.success && response.data) {
        setUser(response.data.user);
        return { success: true, message: 'Signed in successfully!' };
      } else {
        return { success: false, message: response.message || 'Sign in failed' };
      }
    } catch (error) {
      console.error('Sign in error:', error);
      return { success: false, message: 'Network error. Please try again.' };
    }
  };

  const signUp = async (name: string, email: string, password: string) => {
    try {
      const response = await authAPI.signUp({ name, email, password });
      
      if (response.success && response.data) {
        setUser(response.data.user);
        return { success: true, message: 'Account created successfully!' };
      } else {
        return { success: false, message: response.message || 'Sign up failed' };
      }
    } catch (error) {
      console.error('Sign up error:', error);
      return { success: false, message: 'Network error. Please try again.' };
    }
  };

  const signOut = async () => {
    try {
      await authAPI.signOut();
    } catch (error) {
      console.error('Sign out error:', error);
    } finally {
      setUser(null);
    }
  };

  const updateProfile = async (updates: { name?: string; email?: string }) => {
    try {
      const response = await authAPI.updateProfile(updates);
      
      if (response.success && response.data) {
        setUser(response.data.user);
        return { success: true, message: 'Profile updated successfully!' };
      } else {
        return { success: false, message: response.message || 'Update failed' };
      }
    } catch (error) {
      console.error('Update profile error:', error);
      return { success: false, message: 'Network error. Please try again.' };
    }
  };

  const refreshUser = async () => {
    try {
      if (authAPI.isAuthenticated()) {
        const response = await authAPI.getProfile();
        if (response.success && response.data) {
          setUser(response.data.user);
        }
      }
    } catch (error) {
      console.error('Refresh user error:', error);
    }
  };

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user,
    isLoading,
    signIn,
    signUp,
    signOut,
    updateProfile,
    refreshUser,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;