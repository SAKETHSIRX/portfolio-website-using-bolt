// API configuration and service functions
const API_BASE_URL = 'http://localhost:3001/api';

// Types for API responses
export interface User {
  id: number;
  name: string;
  email: string;
  created_at: string;
  updated_at?: string;
  last_login?: string;
}

export interface AuthResponse {
  success: boolean;
  message: string;
  data?: {
    user: User;
    token: string;
  };
  errors?: Array<{
    field: string;
    message: string;
    value: any;
  }>;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message: string;
  data?: T;
  errors?: Array<{
    field: string;
    message: string;
    value: any;
  }>;
}

// Token management
export const tokenManager = {
  get: (): string | null => {
    return localStorage.getItem('auth_token');
  },
  
  set: (token: string): void => {
    localStorage.setItem('auth_token', token);
  },
  
  remove: (): void => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_data');
  },
  
  isValid: (): boolean => {
    const token = tokenManager.get();
    if (!token) return false;
    
    try {
      // Basic JWT structure check
      const parts = token.split('.');
      if (parts.length !== 3) return false;
      
      // Decode payload to check expiration
      const payload = JSON.parse(atob(parts[1]));
      const currentTime = Math.floor(Date.now() / 1000);
      
      return payload.exp > currentTime;
    } catch {
      return false;
    }
  }
};

// User data management
export const userManager = {
  get: (): User | null => {
    const userData = localStorage.getItem('user_data');
    return userData ? JSON.parse(userData) : null;
  },
  
  set: (user: User): void => {
    localStorage.setItem('user_data', JSON.stringify(user));
  },
  
  remove: (): void => {
    localStorage.removeItem('user_data');
  }
};

// HTTP client with automatic token handling
class ApiClient {
  private baseURL: string;

  constructor(baseURL: string) {
    this.baseURL = baseURL;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.baseURL}${endpoint}`;
    
    // Default headers
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    // Add auth token if available
    const token = tokenManager.get();
    if (token && tokenManager.isValid()) {
      headers.Authorization = `Bearer ${token}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      const data = await response.json();

      // Handle token expiration
      if (response.status === 401 || response.status === 403) {
        tokenManager.remove();
        userManager.remove();
        
        // Redirect to auth page if not already there
        if (!window.location.pathname.includes('/auth')) {
          window.location.href = '/auth';
        }
      }

      return data;
    } catch (error) {
      console.error('API request failed:', error);
      return {
        success: false,
        message: 'Network error. Please check your connection.',
      };
    }
  }

  async get<T>(endpoint: string): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, { method: 'GET' });
  }

  async post<T>(endpoint: string, data?: any): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async put<T>(endpoint: string, data?: any): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async delete<T>(endpoint: string): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, { method: 'DELETE' });
  }
}

// Create API client instance
const apiClient = new ApiClient(API_BASE_URL);

// Authentication API functions
export const authAPI = {
  // Sign up
  signUp: async (userData: {
    name: string;
    email: string;
    password: string;
  }): Promise<AuthResponse> => {
    const response = await apiClient.post<{ user: User; token: string }>(
      '/auth/signup',
      userData
    );

    if (response.success && response.data) {
      tokenManager.set(response.data.token);
      userManager.set(response.data.user);
    }

    return response;
  },

  // Sign in
  signIn: async (credentials: {
    email: string;
    password: string;
  }): Promise<AuthResponse> => {
    const response = await apiClient.post<{ user: User; token: string }>(
      '/auth/signin',
      credentials
    );

    if (response.success && response.data) {
      tokenManager.set(response.data.token);
      userManager.set(response.data.user);
    }

    return response;
  },

  // Sign out
  signOut: async (): Promise<ApiResponse> => {
    const response = await apiClient.post('/auth/signout');
    
    // Clear local storage regardless of response
    tokenManager.remove();
    userManager.remove();
    
    return response;
  },

  // Get current user profile
  getProfile: async (): Promise<ApiResponse<{ user: User }>> => {
    return apiClient.get('/auth/profile');
  },

  // Update profile
  updateProfile: async (updates: {
    name?: string;
    email?: string;
  }): Promise<ApiResponse<{ user: User }>> => {
    const response = await apiClient.put<{ user: User }>(
      '/auth/profile',
      updates
    );

    if (response.success && response.data) {
      userManager.set(response.data.user);
    }

    return response;
  },

  // Change password
  changePassword: async (passwords: {
    currentPassword: string;
    newPassword: string;
  }): Promise<ApiResponse> => {
    return apiClient.put('/auth/change-password', passwords);
  },

  // Check if user is authenticated
  isAuthenticated: (): boolean => {
    return tokenManager.isValid() && userManager.get() !== null;
  },

  // Get current user
  getCurrentUser: (): User | null => {
    return userManager.get();
  },
};

// Health check
export const healthCheck = async (): Promise<ApiResponse> => {
  return apiClient.get('/auth/health');
};

export default apiClient;