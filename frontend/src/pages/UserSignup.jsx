import { supabase } from '../lib/supabase';
import { useState } from 'react';
import axios from 'axios';

function UserSignup() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [companyId, setCompanyId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleUserSignup(e) {
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
      
      // Step 2: Call the backend to request joining a company
      // Using the proxy configuration
      const response = await axios.post('/api/signup/user', {
        company_id: companyId,
        user_id: data.user.id,
      });
      
      console.log("Backend response:", response.data);
      alert('Signup successful! Wait for admin approval.');
    } catch (err) {
      console.error('Signup error:', err);
      setError(err.message || 'An error occurred during signup');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="signup-container">
      <h1>User Signup</h1>
      {error && <div className="error-message">{error}</div>}
      
      <form onSubmit={handleUserSignup}>
        <div className="form-group">
          <label htmlFor="companyId">Company ID</label>
          <input 
            id="companyId"
            value={companyId}
            onChange={(e) => setCompanyId(e.target.value)}
            placeholder="Enter your company ID" 
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
          {loading ? 'Signing up...' : 'Sign Up as User'}
        </button>
      </form>
    </div>
  );
}

export default UserSignup;