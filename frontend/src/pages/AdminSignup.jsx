import { supabase } from '../lib/supabase';
import { useState } from 'react';
import axios from 'axios';

function AdminSignup() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [companyName, setCompanyName] = useState('');

  async function handleAdminSignup() {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    });

    if (error) {
      console.error('Signup error:', error.message);
      return;
    }

    // Call your FastAPI backend to create company + admin
    await axios.post(`${import.meta.env.VITE_BACKEND_URL}/api/signup/admin`, {
      company_name: companyName,
      user_id: data.user.id,
    });

    alert('Signup successful! Check your email to confirm.');
  }

  return (
    <div>
      <h1>Admin Signup</h1>
      <input placeholder="Company Name" onChange={(e) => setCompanyName(e.target.value)} />
      <input placeholder="Email" onChange={(e) => setEmail(e.target.value)} />
      <input placeholder="Password" type="password" onChange={(e) => setPassword(e.target.value)} />
      <button onClick={handleAdminSignup}>Sign Up as Admin</button>
    </div>
  );
}

export default AdminSignup;
