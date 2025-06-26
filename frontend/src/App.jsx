import './App.css'
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import AdminSignup from './pages/AdminSignup'
import UserSignup from './pages/UserSignup'
import LoginPage from './pages/loginPage';
import AdminDashboardPage from './pages/AdminDashboardPage';
import HomePage from './pages/HomePage';
import NotAuthorizedPage from './pages/NotAuthorizedPage';

function App() {
  return (
    <Router>
      <div className="app-container">
        <nav className="navbar flex justify-between items-center p-4 bg-gray-800 text-white">
          <Link to="/">Home</Link>
          <Link to="/signup/admin">Admin Signup</Link>
          <Link to="/signup/user">User Signup</Link>
          <Link to="/login">Login</Link>
        </nav>

        <Routes>
          <Route path="/signup/admin" element={<AdminSignup />} />
          <Route path="/signup/user" element={<UserSignup />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/admin-dashboard" element={<AdminDashboardPage />} />
          <Route path="/not-authorized" element={<NotAuthorizedPage />} />
          <Route path="/" element={<HomePage />} />
          <Route path="*" element={<h1>404 Not Found</h1>} />
        </Routes>
      </div>
    </Router>
  )
}

export default App;