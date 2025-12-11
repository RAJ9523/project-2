import React from 'react';
import { Container, Grid, Typography, Button, Box, Card, CardContent } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { Link } from 'react-router-dom';
import { Pie } from 'react-chartjs-2';
import { Chart as ChartJS, Title, Tooltip, Legend, ArcElement } from 'chart.js';
import RecentInvestments from '../components/RecentInvestments';
import Header from './Header';
ChartJS.register(Title, Tooltip, Legend, ArcElement);



const HomePage = () => {
  const navigate = useNavigate();
  const user = localStorage.getItem('username') || 'User';

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    navigate('/login');
  };

  const investmentData = {
    labels: ['Stocks', 'Mutual Funds', 'Fixed Deposits'],
    datasets: [
      {
        data: [50, 30, 20],
        backgroundColor: ['#ff6b6b', '#51cf66', '#4dabf7'],
        hoverOffset: 4
      }
    ]
  };

  return (
    <>
    <Header></Header>
    <Box 
      sx={{
        minHeight: "100vh",
        background: "linear-gradient(to bottom right, #dfe9f3, #ffffff)",
        paddingBottom: 5
      }}
    >
      {/* HEADER */}
      

      <Container maxWidth="lg" sx={{ mt: 4 }}>

        {/* WELCOME */}
        <Typography variant="h4" sx={{ fontWeight: 'bold', mb: 3 }}>
          Welcome, {user}! 👋
        </Typography>

        {/* OVERVIEW SECTION */}
        <Grid container spacing={4}>
          
          {/* Total Portfolio */}
          <Grid item xs={12} md={6}>
            <Card sx={{ padding: 2, borderRadius: 3, boxShadow: 5 }}>
              <CardContent>
                <Typography variant="h6" sx={{ fontWeight: 'bold' }}>Investment Overview</Typography>
                <Typography variant="h4" sx={{ mt: 2, color: "#1976d2" }}>
                  Total Portfolio Value: $50,000
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          {/* PIE CHART */}
          <Grid item xs={12} md={6}>
            <Card sx={{ padding: 3, borderRadius: 3, textAlign: "center", boxShadow: 5 }}>
              <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
                Investment Distribution
              </Typography>
              <Pie data={investmentData} />
            </Card>
          </Grid>

        </Grid>

        {/* RECENT INVESTMENTS */}
        <Link to="/recent-investment" style={{ textDecoration: 'none' }}>
      <Card sx={{ mt: 5, padding: 3, borderRadius: 3, boxShadow: 4 }}>
        <CardContent>
          <Typography variant="h6" sx={{ fontWeight: 'bold', mb: 2 }}>
            Recent Investments
          </Typography>

          <table style={{ width: '100%', fontSize: "16px" }}>
            <thead>
              <tr style={{ fontWeight: 'bold' }}>
                <td>Investment</td>
                <td>Amount</td>
                <td>Type</td>
              </tr>
            </thead>

            <tbody>
              <tr><td>Amazon Stocks</td><td>$10,000</td><td>Stocks</td></tr>
              <tr><td>Vanguard Mutual Fund</td><td>$5,000</td><td>Mutual Funds</td></tr>
              <tr><td>HDFC Fixed Deposit</td><td>$2,000</td><td>Fixed Deposits</td></tr>
            </tbody>
          </table>
        </CardContent>
      </Card>
    </Link>

        {/* QUICK ACTION BUTTONS */}
        <Grid container spacing={3} sx={{ mt: 4 }}>
          <Grid item xs={12} md={6}>
            <Button fullWidth variant="contained" size="large" sx={{ padding: 2 }} onClick={() => navigate('/add-investment')}>
              ➕ Add New Investment
            </Button>
          </Grid>
          <Grid item xs={12} md={6}>
            <Button fullWidth variant="contained" size="large" sx={{ padding: 2 }} onClick={() => navigate('/view-investment')}>
              📄 View All Investments
            </Button>
          </Grid>
        </Grid>

        {/* ANALYTICS SECTION */}
        <Card sx={{ mt: 5, padding: 3, height: 300, borderRadius: 3, boxShadow: 4 }}>
          <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
            Portfolio Growth Over Time
          </Typography>
          <Box sx={{ height: 240, background: "#e9ecef", borderRadius: 2, mt: 2 }} />
        </Card>

        {/* STOCK MARKET IMAGE */}
        <Box sx={{ mt: 4, textAlign: "center" }}>
          <img 
            src="https://images.unsplash.com/photo-1569025690938-a00729c9e83f" 
            alt="Stock Market" 
            style={{ width: "100%", borderRadius: 12, boxShadow: "0px 4px 20px rgba(0,0,0,0.2)" }} 
          />
        </Box>

      </Container>

      {/* FOOTER */}
      <Box sx={{ mt: 4, padding: 2, backgroundColor: "#1976d2", color: "white", textAlign: "center" }}>
        © 2025 Investment Tracker
      </Box>

    </Box>
    </>
  );
};

export default HomePage;
