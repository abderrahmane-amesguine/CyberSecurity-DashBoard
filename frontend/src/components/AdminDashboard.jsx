// src/components/AdminDashboardContent.jsx
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { supabase } from '../lib/supabase';

export default function AdminDashboardContent({ userData }) {
  const [companies, setCompanies] = useState([]);
  const [pendingUsers, setPendingUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        
        // Get the current session for the auth token
        const { data: { session } } = await supabase.auth.getSession();
        
        if (!session) {
          console.error('No active session');
          return;
        }
        
        // Use the token for authenticated API requests
        const accessToken = session.access_token;
        const headers = {
          'Authorization': `Bearer ${accessToken}`
        };
        
        // Fetch all users in the companie using your backend API
        const companiesResponse = await axios.get(
          `${import.meta.env.VITE_BACKEND_URL}/api/admin/all-users`, 
          { headers }
        );

        console.log('Companies response:', companiesResponse);
        
        setCompanies(companiesResponse.data || []);
        
        // Fetch pending users using your backend API
        const pendingUsersResponse = await axios.get(
          `${import.meta.env.VITE_BACKEND_URL}/api/admin/pending-users`, 
          { headers }
        );
        
        setPendingUsers(pendingUsersResponse.data || []);
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };
    
    fetchDashboardData();
  }, []);

  const handleApproveUser = async (userId) => {
    try {
      const { data: { session } } = await supabase.auth.getSession();
      
      await axios.post(
        `${import.meta.env.VITE_BACKEND_URL}/api/users/${userId}/approve`,
        {},
        {
          headers: {
            'Authorization': `Bearer ${session.access_token}`
          }
        }
      );
      
      // Remove the approved user from the list
      setPendingUsers(pendingUsers.filter(user => user.id !== userId));
    } catch (error) {
      console.error('Error approving user:', error);
      alert('Failed to approve user. Please try again.');
    }
  };

  const handleDenyUser = async (userId) => {
    try {
      const { data: { session } } = await supabase.auth.getSession();
      
      await axios.post(
        `${import.meta.env.VITE_BACKEND_URL}/api/users/${userId}/deny`,
        {},
        {
          headers: {
            'Authorization': `Bearer ${session.access_token}`
          }
        }
      );
      
      // Remove the denied user from the list
      setPendingUsers(pendingUsers.filter(user => user.id !== userId));
    } catch (error) {
      console.error('Error denying user:', error);
      alert('Failed to deny user. Please try again.');
    }
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <header className="mb-8">
        <h1 className="text-3xl font-bold">Admin Dashboard</h1>
        {userData && (
          <p className="text-gray-600">
            Welcome, {userData.email}
          </p>
        )}
      </header>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Companies Section */}
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Companies</h2>
          {loading ? (
            <p className="text-gray-500">Loading companies...</p>
          ) : companies.length > 0 ? (
            <ul className="divide-y">
              {companies.map((company) => (
                <li key={company.id} className="py-3">
                  <div className="flex justify-between items-center">
                    <div>
                      <span className="font-medium">{company.email}</span>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-gray-500">No companies found</p>
          )}
        </div>
        
        {/* Pending Users Section */}
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Pending User Requests</h2>
          {loading ? (
            <p className="text-gray-500">Loading requests...</p>
          ) : pendingUsers.length > 0 ? (
            <ul className="divide-y">
              {pendingUsers.map((user) => (
                <li key={user.id} className="py-3">
                  <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2">
                    <div>
                      <p className="font-medium">{user.email}</p>
                    </div>
                    <div className="flex space-x-2">
                      <button 
                        onClick={() => handleApproveUser(user.id)}
                        className="px-3 py-1 bg-green-500 text-white rounded hover:bg-green-600"
                      >
                        Approve
                      </button>
                      <button 
                        onClick={() => handleDenyUser(user.id)}
                        className="px-3 py-1 bg-red-500 text-white rounded hover:bg-red-600"
                      >
                        Deny
                      </button>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-gray-500">No pending requests</p>
          )}
        </div>
      </div>
    </div>
  );
}