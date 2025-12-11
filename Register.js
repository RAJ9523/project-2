import React, { useState } from 'react';
import { TextField, Button, Typography, Container, Box, InputAdornment } from '@mui/material';
import { Phone } from '@mui/icons-material'; // For icons
import { useNavigate } from 'react-router-dom'; // Import useNavigate

const Register = () => {
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [pan, setPan] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errors, setErrors] = useState({}); // To store validation errors
  const navigate = useNavigate(); // Initialize useNavigate

  const validateEmail = (email) => {
    const regex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    return regex.test(email);
  };

  const validatePhone = (phone) => {
    const regex = /^[0-9]{10}$/; // Validates 10 digit phone numbers
    return regex.test(phone);
  };

  const validatePAN = (pan) => {
    const regex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/; // PAN format validation (example)
    return regex.test(pan);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    const validationErrors = {};

    // Validation checks
    if (!email || !validateEmail(email)) {
      validationErrors.email = 'Please enter a valid email.';
    }

    if (!phone || !validatePhone(phone)) {
      validationErrors.phone = 'Phone number must be 10 digits.';
    }

   
    if (!password || password.length < 6 || password.length > 20) {
      validationErrors.password = 'Password must be between 6 and 20 characters.';
    }

    if (password !== confirmPassword) {
      validationErrors.confirmPassword = 'Passwords do not match.';
    }

    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      return;
    }

    const data = {
      email: email,
      phone: phone,
      pan: pan,
      password: password,
    };

    try {
      // Send POST request to backend API (replace URL with your backend URL)
      const response = await fetch('http://127.0.0.1:5000/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),  // Send the data as JSON
      });

      if (!response.ok) {
        throw new Error('Registration failed');
      }

      const result = await response.json();
      console.log(result); 

      // Redirect to login page after successful registration
      navigate('/login');  // Navigate to the login page
    } catch (error) {
      setErrors({ message: error.message });
      console.error(error);
    }
  };

  return (
    <Container maxWidth="xs" sx={{ display: 'flex', justifyContent: 'center', height: '100vh', alignItems: 'center' }}>
      <Box component="form" onSubmit={handleSubmit} sx={{ width: '100%', backgroundColor: 'white', padding: 4, borderRadius: 2, boxShadow: 3 }}>
        <Typography variant="h5" component="h1" align="center" gutterBottom>
          Register
        </Typography>

        {errors.message && <Typography color="error">{errors.message}</Typography>}

        <TextField
          label="Email"
          variant="outlined"
          fullWidth
          margin="normal"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          error={Boolean(errors.email)}
          helperText={errors.email}
        />

        <TextField
          label="Phone"
          variant="outlined"
          fullWidth
          margin="normal"
          value={phone}
          onChange={(e) => setPhone(e.target.value)}
          required
          error={Boolean(errors.phone)}
          helperText={errors.phone}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Phone />
              </InputAdornment>
            ),
          }}
        />

        <TextField
          label="PAN"
          variant="outlined"
          fullWidth
          margin="normal"
          value={pan}
          onChange={(e) => setPan(e.target.value)}
          required
          error={Boolean(errors.pan)}
          helperText={errors.pan}
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
          error={Boolean(errors.password)}
          helperText={errors.password}
        />

        <TextField
          label="Confirm Password"
          variant="outlined"
          type="password"
          fullWidth
          margin="normal"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          required
          error={Boolean(errors.confirmPassword)}
          helperText={errors.confirmPassword}
        />

        <Button
          type="submit"
          variant="contained"
          color="primary"
          fullWidth
          sx={{ marginTop: 2 }}
        >
          Register
        </Button>
      </Box>
    </Container>
  );
};

export default Register;
