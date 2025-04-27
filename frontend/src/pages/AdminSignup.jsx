import { supabase } from '../lib/supabase';
import { useState } from 'react';
import axios from 'axios';

function AdminSignup() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [companyName, setCompanyName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleAdminSignup(e) {
    e.preventDefault();
    setLoading(true);
    setError('');
    
    try {
      // Step 1: Sign up with Supabase Auth
      const { data, error: authError } = await supabase.auth.signUp({
        email,
        password,
      });

      if (authError) {
        throw new Error(`Authentication error: ${authError.message}`);
      }

      console.log("Supabase auth successful, user ID:", data.user.id);
      
      // Step 2: Call backend to create company and link admin
      // Using the proxy configuration - notice we're not using VITE_BACKEND_URL anymore
      const response = await axios.post('/api/signup/admin', {
        company_name: companyName,
        admin_email: email,
      });
      
      console.log("Backend response:", response.data);
      alert('Signup successful! Check your email to confirm.');
    } catch (err) {
      console.error('Signup error:', err);
      setError(err.message || 'An error occurred during signup');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="signup-container">
      <h1>Admin Signup</h1>
      {error && <div className="error-message">{error}</div>}
      
      <form onSubmit={handleAdminSignup}>
        <div className="form-group">
          <label htmlFor="companyName">Company Name</label>
          <input 
            id="companyName"
            value={companyName}
            onChange={(e) => setCompanyName(e.target.value)}
            placeholder="Enter your company name" 
            required
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="email">Email</label>
          <input 
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter your email" 
            required
          />
        </div>
        
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input 
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Create a password" 
            required
          />
        </div>
        
        <button type="submit" disabled={loading}>
          {loading ? 'Signing up...' : 'Sign Up as Admin'}
        </button>
      </form>
    </div>
  );
}

export default AdminSignup;