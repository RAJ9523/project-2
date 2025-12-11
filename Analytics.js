import React, { useState, useEffect } from 'react';
import { Box, Card, CardContent, Typography } from '@mui/material';
import { Line } from 'react-chartjs-2';
import { Chart as ChartJS, Title, Tooltip, Legend, LineElement, CategoryScale, LinearScale, PointElement } from 'chart.js';
import { useNavigate } from 'react-router-dom';

// Register required chart components
ChartJS.register(Title, Tooltip, Legend, LineElement, CategoryScale, LinearScale, PointElement);

const Analytics = () => {
  const [analyticsData, setAnalyticsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  // Simulate fetching portfolio growth data from the backend
  useEffect(() => {
    const fetchAnalyticsData = async () => {
      const token = localStorage.getItem('access_token');
      if (!token) {
        alert('Please log in first');
        navigate('/login');
        return;
      }

      // Dummy data (replace this with real backend call)
      const data = {
        labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July'], // Months
        datasets: [
          {
            label: 'Portfolio Growth',
            data: [10000, 12000, 15000, 16000, 19000, 21000, 25000], // Portfolio values over time
            borderColor: '#1976d2',
            backgroundColor: 'rgba(25, 118, 210, 0.2)', // Lighter background color for the line
            fill: true, // Fill the area under the line
            tension: 0.4, // Smooth the line
            pointRadius: 5,
            pointBackgroundColor: '#1976d2',
          },
        ],
      };

      setAnalyticsData(data); // Set the fetched data
      setLoading(false); // Stop loading
    };

    fetchAnalyticsData();
  }, [navigate]);

  return (
    <Box
      sx={{
        minHeight: '100vh',
        background: 'url(/images/stock-market.jpg) no-repeat center center fixed',
        backgroundSize: 'cover',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
      }}
    >
      {/* Header Section */}
      <Header /> {/* Reusable header component */}

      <Card sx={{ mt: 5, padding: 3, borderRadius: 3, boxShadow: 4, maxWidth: '90%' }}>
        <CardContent>
          <Typography variant="h5" sx={{ fontWeight: 'bold', textAlign: 'center', mb: 3 }}>
            Portfolio Growth Over Time
          </Typography>

          {/* Loading Spinner */}
          {loading ? (
            <Typography variant="h6" sx={{ color: 'white', mt: 4, textAlign: 'center' }}>
              Loading analytics...
            </Typography>
          ) : (
            <Line
              data={analyticsData}
              options={{
                responsive: true,
                plugins: {
                  title: {
                    display: true,
                    text: 'Portfolio Growth Over Time',
                  },
                  tooltip: {
                    callbacks: {
                      label: (tooltipItem) => {
                        return `$${tooltipItem.raw.toLocaleString()}`; // Format value as currency
                      },
                    },
                  },
                },
                scales: {
                  x: {
                    title: {
                      display: true,
                      text: 'Months',
                    },
                  },
                  y: {
                    title: {
                      display: true,
                      text: 'Portfolio Value ($)',
                    },
                    ticks: {
                      beginAtZero: true,
                    },
                  },
                },
              }}
            />
          )}
        </CardContent>
      </Card>

      {/* Button to go back to Home */}
      <Box sx={{ mt: 3 }}>
        <button
          onClick={() => navigate('/home')}
          style={{
            padding: '10px 20px',
            fontSize: '16px',
            backgroundColor: '#1976d2',
            color: 'white',
            border: 'none',
            borderRadius: '5px',
            cursor: 'pointer',
          }}
        >
          Back to Home
        </button>
      </Box>
    </Box>
  );
};

export default Analytics;
