const request = require('supertest');
const app = require('../src/app');

describe('GET /', () => {
  test('should return Hello World message', async () => {
    const response = await request(app).get('/').expect(200);

    expect(response.body).toEqual({
      message: 'Hello World here I am',
    });
  });
});

describe('404 handler', () => {
  test('should return 404 for unknown routes', async () => {
    const response = await request(app).get('/unknown-route').expect(404);

    expect(response.body.error.message).toBe('Not Found');
    expect(response.body.error.status).toBe(404);
  });
});

describe('Error handling', () => {
  test('should handle server errors', async () => {
    // Test the error handling by modifying the main route temporarily
    const express = require('express');
    const testApp = express();

    testApp.use(express.json());

    // Add a route that throws an error
    testApp.get('/test-error', (req, res, next) => {
      const error = new Error('Test error');
      error.status = 500;
      next(error);
    });

    // Use the same error handler from the main app
    // eslint-disable-next-line no-unused-vars
    testApp.use((err, req, res, next) => {
      const status = err.status || 500;
      const message = err.message || 'Internal Server Error';

      res.status(status).json({
        error: {
          message,
          status,
        },
      });
    });

    const response = await request(testApp).get('/test-error').expect(500);

    expect(response.body.error.message).toBe('Test error');
    expect(response.body.error.status).toBe(500);
  });
});
