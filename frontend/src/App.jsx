import './App.css'
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom'
import AdminSignup from './pages/AdminSignup'
import UserSignup from './pages/UserSignup'

function App() {
  return (
    <Router>
      <div className="app-container">
        <nav>
          <Link to="/">Home</Link>
          <Link to="/signup/admin">Admin Signup</Link>
          <Link to="/signup/user">User Signup</Link>
        </nav>

        <Routes>
          <Route path="/signup/admin" element={<AdminSignup />} />
          <Route path="/signup/user" element={<UserSignup />} />
          <Route path="/" element={<HomePage />} />
        </Routes>
      </div>
    </Router>
  )
}

function HomePage() {
  return (
    <div className="home-container">
      <h1>CyberSecurity Dashboard</h1>
      <p>Welcome to the cybersecurity management platform. Please choose your signup type:</p>
      
      <div className="home-links">
        <Link to="/signup/admin">Sign up as Admin</Link>
        <Link to="/signup/user">Sign up as User</Link>
      </div>
    </div>
  );
}

export default App