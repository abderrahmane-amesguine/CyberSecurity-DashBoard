import { supabase } from '../lib/supabase';
import { useState } from 'react';
import axios from 'axios';

function UserSignup() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [companyId, setCompanyId] = useState('');

  async function handleUserSignup() {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    });

    if (error) {
      console.error('Signup error:', error.message);
      return;
    }

    // Call your FastAPI backend to request joining a company
    await axios.post('/api/signup/user', {
      company_id: companyId,
      user_id: data.user.id,
    });

    alert('Signup successful! Wait for admin approval.');
  }

  return (
    <div>
      <h1>User Signup</h1>
      <input placeholder="Company ID" onChange={(e) => setCompanyId(e.target.value)} />
      <input placeholder="Email" onChange={(e) => setEmail(e.target.value)} />
      <input placeholder="Password" type="password" onChange={(e) => setPassword(e.target.value)} />
      <button onClick={handleUserSignup}>Sign Up as User</button>
    </div>
  );
}

export default UserSignup;
