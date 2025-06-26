import React from 'react';
import { Link } from 'react-router-dom';

function HomePage() {
    return (
        <div className="home-container">
            <h1>CyberSecurity Dashboard</h1>
            <p>Welcome to the cybersecurity management platform. Please choose your signup type:</p>

            <div className="home-links flex flex-col gap-4">
                <Link to="/signup/admin">Sign up as Admin</Link>
                <Link to="/signup/user">Sign up as User</Link>
            </div>
        </div>
    );
}

export default HomePage;