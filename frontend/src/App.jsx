import './App.css'
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom'
import AdminSignup from './pages/AdminSignup'
import UserSignup from './pages/UserSignup'

function App() {
  return (
    <Router>
      <div>
        <nav>
          <Link to="/signup/admin">Admin Signup</Link>
          <Link to="/signup/user">User Signup</Link>
        </nav>

        <Routes>
          <Route path="/signup/admin" element={<AdminSignup />} />
          <Route path="/signup/user" element={<UserSignup />} />
          <Route path="/" element={
            <div>
              <h1>Welcome to CyberSecurity Dashboard</h1>
              <p>Please choose your signup type:</p>
              <div>
                <Link to="/signup/admin">Sign up as Admin</Link>
                <Link to="/signup/user">Sign up as User</Link>
              </div>
            </div>
          } />
        </Routes>
      </div>
    </Router>
  )
}

export default App
