// Header.js
import React from 'react';
import { Box, Typography, Button } from '@mui/material';
import { useNavigate } from 'react-router-dom';

const Header = () => {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    navigate('/login');
  };

  return (
    <Box 
      sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        padding: 2, 
        backgroundColor: '#1976d2', 
        color: 'white', 
        boxShadow: 3,
        alignItems: 'center'
      }}
    >
      {/* Logo */}
      <Typography variant="h5" sx={{ fontWeight: 'bold' }}>
        Investment Tracker
      </Typography>

      {/* Navigation Links */}
      <Box>
        <Button color="inherit" onClick={() => navigate('/home')}>Home</Button>
        <Button color="inherit" onClick={() => navigate('/add-investment')}>Add Investment</Button>
        <Button color="inherit" onClick={() => navigate('/view-investments')}>View Investments</Button>
        <Button color="inherit" onClick={handleLogout}>Logout</Button>
      </Box>
    </Box>
  );
};

export default Header;  // Ensure the default export is here
