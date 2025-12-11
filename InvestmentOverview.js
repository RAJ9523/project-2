import React, { useState, useEffect } from 'react';
import { Container, Box, Typography, Card, CardContent } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import Header from '../pages/Header';

const InvestmentOverview = () => {
  const [totalPortfolioValue, setTotalPortfolioValue] = useState(0);
  const [investmentDistribution, setInvestmentDistribution] = useState({
    stocks: 0,
    mutualFunds: 0,
    fixedDeposits: 0,
  });
  const navigate = useNavigate();

  // Simulate fetching investment overview data
  useEffect(() => {
    const fetchInvestmentOverview = async () => {
      const token = localStorage.getItem('access_token');
      if (!token) {
        alert('Please log in first');
        navigate('/login');
        return;
      }

      // Sample data (you can replace this with an actual API call)
      const totalValue = 50000;
      const distribution = {
        stocks: 20000,
        mutualFunds: 15000,
        fixedDeposits: 10000,
      };

      setTotalPortfolioValue(totalValue);
      setInvestmentDistribution(distribution);
    };

    fetchInvestmentOverview();
  }, [navigate]);

  return (
    <Box 
      sx={{
        minHeight: '100vh',
        background: 'url(/images/stock-market.jpg) no-repeat center center fixed', // Background image
        backgroundSize: 'cover',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
      }}
    >
      {/* Header Section */}
      <Header /> {/* Reusable header component */}

      <Container maxWidth="lg" sx={{ mt: 5, position: 'relative', zIndex: 1 }}>
        <Box 
          sx={{
            padding: 3,
            backgroundColor: 'rgba(255, 255, 255, 0.8)', // Semi-transparent background for the content
            borderRadius: 2,
            boxShadow: 3,
            backdropFilter: 'blur(10px)', // Optional: Blur the background slightly for better visibility of content
          }}
        >
          <Typography variant="h5" align="center" sx={{ marginBottom: 3, color: 'black' }}>
            Investment Overview
          </Typography>

          {/* Total Portfolio Value */}
          <Card sx={{ mb: 3, backgroundColor: 'rgba(255, 255, 255, 0.9)' }}>
            <CardContent>
              <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                Total Portfolio Value
              </Typography>
              <Typography variant="h4" sx={{ mt: 2, color: "#1976d2" }}>
                ${totalPortfolioValue}
              </Typography>
            </CardContent>
          </Card>

          {/* Investment Distribution */}
          <Card sx={{ mb: 3, backgroundColor: 'rgba(255, 255, 255, 0.9)' }}>
            <CardContent>
              <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                Investment Distribution
              </Typography>
              <Typography variant="body1">
                Stocks: ${investmentDistribution.stocks}
              </Typography>
              <Typography variant="body1">
                Mutual Funds: ${investmentDistribution.mutualFunds}
              </Typography>
              <Typography variant="body1">
                Fixed Deposits: ${investmentDistribution.fixedDeposits}
              </Typography>
            </CardContent>
          </Card>

          {/* Button to go back to Home */}
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
  );
};

export default InvestmentOverview;
