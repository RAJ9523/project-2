import React, { useState } from 'react';
import { Container, Box, Typography, TextField, Button, MenuItem, Select, InputLabel, FormControl } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import Header from '../pages/Header';

const AddInvestment = () => {
  const [type, setType] = useState('');
  const [name, setName] = useState('');
  const [amount, setAmount] = useState('');
  const [returnRate, setReturnRate] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
  
    // Get token and user_id from localStorage
    const token = localStorage.getItem('access_token');
    const userId = localStorage.getItem('user_id');  // Assuming user_id is stored in localStorage after login
  
    // Check if the token and user_id exist
    if (!token || !userId) {
      alert('Please log in first');
      navigate('/login');
      return;
    }
  
    // Prepare investment data
    const investmentData = {
      user_id: userId,  // Send user_id in the request body
      type,
      name,
      amount: parseFloat(amount),
      returnRate: parseFloat(returnRate),
    };
  
    try {
      const response = await fetch('http://localhost:5000/investment', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,  // Bearer token for authentication
        },
        body: JSON.stringify(investmentData),  // Send the user_id along with other investment data
      });
  
      const result = await response.json();
      if (response.ok) {
        alert('Investment added successfully');
        navigate('/home');  // Redirect to home page or investment list
      } else {
        alert(result.error || 'Failed to add investment');
      }
    } catch (error) {
      console.error(error);
      alert('Error while adding investment');
    }
  };
  
  return (
  <>
    <Header /> 

    <Box 
      sx={{
        minHeight: '100vh',
        background: 'url(/stock-1.avif) no-repeat center center fixed', // Path to your background image
        backgroundSize: 'cover',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
      }}
    >
   

      <Container maxWidth="sm" sx={{ mt: 5, position: 'relative', zIndex: 1 }}>
        <Box 
          component="form" 
          onSubmit={handleSubmit} 
          sx={{
            padding: 3,
            backgroundColor: 'rgba(255, 255, 255, 0)', // Fully transparent background
            borderRadius: 2,
            boxShadow: 3,
            backdropFilter: 'blur(10px)', // Optional: Blur the background slightly for better visibility of form fields
          }}
        >
          <Typography variant="h5" align="center" sx={{ marginBottom: 3, color: 'white' }}>
            Add New Investment
          </Typography>

          {/* Investment Type Dropdown */}
          <FormControl fullWidth margin="normal" required>
            <InputLabel sx={{ color: 'white' }}>Investment Type</InputLabel>
            <Select
              value={type}
              onChange={(e) => setType(e.target.value)}
              label="Investment Type"
              sx={{
                color: 'white',
                '.MuiOutlinedInput-notchedOutline': { borderColor: 'white' }, // Border color white
                '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: 'white' }, // Hover border color white
              }}
            >
              <MenuItem value="stock">Stock</MenuItem>
              <MenuItem value="mutual-fund">Mutual Fund</MenuItem>
              <MenuItem value="fixed-deposit">Fixed Deposit</MenuItem>
            </Select>
          </FormControl>

          {/* Investment Name */}
          <TextField
            label="Investment Name"
            fullWidth
            margin="normal"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            sx={{
              input: { color: 'white' },
              label: { color: 'white' },
              '.MuiOutlinedInput-notchedOutline': { borderColor: 'white' },
              '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: 'white' },
            }}
          />

          {/* Investment Amount */}
          <TextField
            label="Amount"
            fullWidth
            margin="normal"
            type="number"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            required
            sx={{
              input: { color: 'white' },
              label: { color: 'white' },
              '.MuiOutlinedInput-notchedOutline': { borderColor: 'white' },
              '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: 'white' },
            }}
          />

          {/* Return Rate */}
          <TextField
            label="Return Rate (%)"
            fullWidth
            margin="normal"
            type="number"
            value={returnRate}
            onChange={(e) => setReturnRate(e.target.value)}
            required
            sx={{
              input: { color: 'white' },
              label: { color: 'white' },
              '.MuiOutlinedInput-notchedOutline': { borderColor: 'white' },
              '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: 'white' },
            }}
          />

          <Button type="submit" variant="contained" color="primary" fullWidth sx={{ marginTop: 2 }}>
            Add Investment
          </Button>
        </Box>
      </Container>
    </Box>
    </>
  );
};

export default AddInvestment;
