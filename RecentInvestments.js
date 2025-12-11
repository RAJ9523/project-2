import React, { useState, useEffect } from 'react';
import { Container, Box, Typography, Button, Card, CardContent } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import Header from '../pages/Header';

const RecentInvestments = () => {
  const [recentInvestments, setRecentInvestments] = useState([]);
  const navigate = useNavigate();

  // Simulate fetching recent investments from a backend
  useEffect(() => {
    const fetchInvestments = async () => {
      const token = localStorage.getItem('access_token');
      if (!token) {
        alert('Please log in first');
        navigate('/login');
        return;
      }

      // Sample investment data (you can replace this with an actual API call)
      const investments = [
        { id: 1, name: 'Amazon Stocks', amount: 10000, type: 'Stock' },
        { id: 2, name: 'Vanguard Mutual Fund', amount: 5000, type: 'Mutual Fund' },
        { id: 3, name: 'HDFC Fixed Deposit', amount: 2000, type: 'Fixed Deposit' }
      ];

      setRecentInvestments(investments);
    };

    fetchInvestments();
  }, [navigate]);

  return (
    <>

<Header /> 
    
    <Box 
      sx={{
        minHeight: '100vh',
        background: 'url(/images/stock-market.jpg) no-repeat center center fixed', // Path to your background image
        backgroundSize: 'cover',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
      }}
    >
{/*       Header Section */}
     

      <Container maxWidth="lg" sx={{ mt: 5, position: 'relative', zIndex: 1 }}>
        <Box 
          sx={{
            padding: 3,
            backgroundColor: 'rgba(255, 255, 255, 0.8)', // Semi-transparent white background for the content
            borderRadius: 2,
            boxShadow: 3,
            backdropFilter: 'blur(10px)', // Optional: Blur the background slightly for better visibility of content
          }}
        >
          <Typography variant="h5" align="center" sx={{ marginBottom: 3, color: 'black' }}>
            Recent Investments
          </Typography>

          {/* List Recent Investments */}
          {recentInvestments.map((investment) => (
            <Card key={investment.id} sx={{ mb: 3, backgroundColor: 'rgba(255, 255, 255, 0.9)' }}>
              <CardContent>
                <Typography variant="h6">{investment.name}</Typography>
                <Typography variant="body1">Amount: ${investment.amount}</Typography>
                <Typography variant="body2" color="textSecondary">Type: {investment.type}</Typography>
              </CardContent>
            </Card>
          ))}

          {/* Button to go back to Home or Add Investment */}
          <Button 
            variant="contained" 
            color="primary" 
            fullWidth 
            sx={{ marginTop: 2 }}
            onClick={() => navigate('/home')}
          >
            Back to Home
          </Button>
        </Box>
      </Container>
    </Box>
    </>
  );
};

export default RecentInvestments;
