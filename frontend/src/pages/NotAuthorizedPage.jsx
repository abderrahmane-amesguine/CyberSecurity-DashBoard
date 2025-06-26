import React from 'react';
import { useNavigate } from 'react-router-dom';

const NotAuthorizedPage = () => {
    const navigate = useNavigate();

    const handleGoBack = () => {
        navigate(-1);
    };

    return (
        <div style={styles.container}>
            <h1 style={styles.title}>403 - Not Authorized</h1>
            <p style={styles.message}>You do not have permission to access this page.</p>
            <button style={styles.button} onClick={handleGoBack}>
                Go Back
            </button>
        </div>
    );
};

const styles = {
    container: {
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100vh',
        textAlign: 'center',
        backgroundColor: '#f8f9fa',
    },
    title: {
        fontSize: '2rem',
        color: '#dc3545',
        marginBottom: '1rem',
    },
    message: {
        fontSize: '1.2rem',
        color: '#6c757d',
        marginBottom: '2rem',
    },
    button: {
        padding: '0.5rem 1rem',
        fontSize: '1rem',
        color: '#fff',
        backgroundColor: '#007bff',
        border: 'none',
        borderRadius: '0.25rem',
        cursor: 'pointer',
    },
};

export default NotAuthorizedPage;