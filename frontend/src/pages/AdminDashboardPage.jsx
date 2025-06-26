// src/pages/AdminDashboardPage.jsx
import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { supabase } from '../lib/supabase';
import LoadingSpinner from '../components/LoadingSpinner';
import AdminDashboardContent from '../components/AdminDashboard';
import axios from 'axios';

export default function AdminDashboardPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);
  const [userData, setUserData] = useState(null);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        // First check if the user is authenticated with Supabase
        const { data: { session } } = await supabase.auth.getSession();
        
        if (!session) {
          navigate('/login');
          return;
        }
        
        const { data: response, error: userError } = await supabase.rpc('get_current_user');

        console.log('Response from backend:', response); // Debug log
        
        if (userError) {
          throw new Error('No user data received');
        }
        
        const userData = response.data;
        console.log('User data received:', userData); // Debug log
        
        setUserData(userData);
        
        if (userData?.role === 'admin') {
          setIsAdmin(true);
        } else {
          navigate('/not-authorized');
        }
      } catch (err) {
        console.error('Error checking authentication or role:', err);
        if (err.response?.status === 401) {
          // Unauthorized - token expired or invalid
          navigate('/login');
        } else {
          // Other errors
          navigate('/error', { 
            state: { 
              message: 'Failed to verify your permissions. Please try again later.' 
            }
          });
        }
      } finally {
        setLoading(false);
      }
    };
    
    checkAuth();
  }, [navigate]);

  if (loading) return <LoadingSpinner />;

  return (
    <div className="min-h-screen bg-gray-100">
      {isAdmin && <AdminDashboardContent userData={userData} />}
    </div>
  );
}