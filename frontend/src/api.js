import axios from 'axios';

export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({ baseURL: API_URL, withCredentials: true });

// The JWT now lives in an httpOnly cookie set by the backend.
// The browser attaches it automatically on every request — nothing to do here.

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export default api;