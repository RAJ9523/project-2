import React, { useState, useEffect } from 'react';
import { Box, Card, CardContent, Typography, Grid, Button } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import Header from '../pages/Header';

const ViewInvestments = () => {
  const navigate = useNavigate();
  const [investments, setInvestments] = useState([]); // State to store investments data
  const [loading, setLoading] = useState(true); // Loading state

  // Fetch investments data from the backend
  useEffect(() => {
    const fetchInvestments = async () => {
      const token = localStorage.getItem('access_token');
      if (!token) {
        alert('Please log in first');
        navigate('/login');
        return;
      }

      try {
        const response = await fetch('http://localhost:5000/investments', {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
        });

        const data = await response.json();
        if (response.ok) {
          setInvestments(data.investments);
        } else {
          console.error('Failed to fetch investments:', data.error);
          alert('Failed to load investments');
        }
      } catch (error) {
        console.error('Error fetching investments:', error);
        alert('Error fetching investments');
      } finally {
        setLoading(false); // Stop loading when data is fetched
      }
    };

    fetchInvestments();
  }, [navigate]);

  // Handler for deleting an investment
  const handleDelete = async (investmentId) => {
    console.log('Investment ID:', investmentId);  // Add this log to check the ID
    const token = localStorage.getItem('access_token');
    if (!token) {
      alert('Please log in first');
      navigate('/login');
      return;
    }
  
    try {
      const response = await fetch(`http://localhost:5000/investment/${investmentId}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
  
      const result = await response.json();
      if (response.ok) {
        // Remove the deleted investment from the state
        setInvestments(investments.filter((investment) => investment._id !== investmentId));
        alert('Investment deleted successfully');
      } else {
        alert(result.error || 'Failed to delete investment');
      }
    } catch (error) {
      console.error('Error deleting investment:', error);
      alert('Error deleting investment');
    }
  };

  return (
    <>
      <Header />
      <Box
        sx={{
          minHeight: '100vh',
          background: 'url(/stock-3.jpg) no-repeat center center fixed', // Background image
          backgroundSize: 'cover',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
        }}
      >
        {/* Loading Spinner */}
        {loading ? (
          <Typography variant="h6" sx={{ color: 'white', mt: 4 }}>
            Loading investments...
          </Typography>
        ) : (
          <Grid container spacing={4} sx={{ mt: 5, position: 'relative', zIndex: 1, justifyContent: 'center' }}>
            {/* Loop through the investments and create a box for each */}
            {investments.map((investment) => (
              <Grid item xs={12} sm={6} md={4} key={investment._id}> {/* Use _id from MongoDB */}
                <Card
                  sx={{
                    position: 'relative',
                    padding: 2,
                    borderRadius: 2,
                    boxShadow: 3,
                    backgroundColor: 'rgba(255, 255, 255, 0.7)', // Transparent background
                    backdropFilter: 'blur(5px)', // Optional: Blur effect
                    '&:hover': {
                      transform: 'scale(1.05)',
                      transition: 'transform 0.3s ease-in-out',
                    },
                  }}
                >
                  <Box
                    sx={{
                      height: '200px',
                      backgroundImage: `url('/stock-4.jpg')`, // Default image if not specified
                      backgroundSize: 'cover',
                      backgroundPosition: 'center',
                      borderRadius: 2,
                    }}
                  />
                  <CardContent sx={{ textAlign: 'center', color: 'black' }}>
                    <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                      {investment.name}
                    </Typography>
                    <Typography variant="body1" sx={{ color: '#1976d2' }}>
                      Amount: ${investment.amount}
                    </Typography>

                    {/* Delete Button */}
                    <Button
                      onClick={() => handleDelete(investment._id)} // Pass the investment id to the handler
                      variant="contained"
                      color="error"
                      sx={{ mt: 2 }}
                    >
                      Delete
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}
      </Box>
    </>
  );
};

export default ViewInvestments;
