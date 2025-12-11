import React, { useState } from 'react';
import { TextField, Button, Typography, Container, Box } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState({});  // Correct error state initialization
  const navigate = useNavigate();

  const handleNewUserClick = () => {
    navigate('/register');  // Navigate to the Register page
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    console.log('Form submitted');  // Debugging log to confirm function execution
  
    if (!email || !password) {
      toast.error('Please enter both email and password!');
      return;
    }
  
    const data = {
      email: email,
      password: password,
    };
  
    try {
      console.log('Making request...');  // Log to check if try block is entered
      const response = await fetch('http://localhost:5000/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });
  
      if (response.ok) {
        const result = await response.json();
        
        if (result.access_token) {
          console.log("Access token received:", result.access_token);
          localStorage.setItem('access_token', result.access_token);
          localStorage.setItem('username',email.split('@')[0])
          localStorage.setItem('user_id',result.userid)
          toast.success('Login successful!');
          navigate("/home")
        } else {
          console.log('No access token received!');
          toast.error('Login failed! No token received.');
        }
      } else {
        console.log('Login failed with status:', response.status);
        toast.error('Login failed! Invalid credentials.');
      }
    } catch (error) {
      console.error("Error:", error);
      setErrors({ message: "Failedn" });  // Correct error state management
      toast.error("Failed Login");
    }
  };
  
  return (
    <Container maxWidth="xs">
      <Box component="form" onSubmit={handleSubmit} sx={{ padding: 4, backgroundColor: 'white', borderRadius: 2, boxShadow: 3 }}>
        <Typography variant="h5" component="h1" align="center" gutterBottom>
          Login
        </Typography>

        {errors.message && <Typography color="error">{errors.message}</Typography>}  {/* Display error message if exists */}

        <TextField
          label="Email"
          variant="outlined"
          fullWidth
          margin="normal"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <TextField
          label="Password"
          variant="outlined"
          type="password"
          fullWidth
          margin="normal"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <Button
          type="submit"  // Only use onSubmit for form submission
          variant="contained"
          color="primary"
          fullWidth
          sx={{ marginTop: 2 }}
        >
          Login
        </Button>
        <Button 
          onClick={handleNewUserClick}  // Navigate to the register page on click
          variant="contained" 
          color="secondary" 
          fullWidth
          sx={{ marginTop: 2 }}
        >
          New User
        </Button>

      </Box>
      
      {/* ToastContainer for showing notifications */}
      <ToastContainer />
    </Container>
  );
};

export default Login;
