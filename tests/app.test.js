const request = require('supertest');
const app = require('../src/app');

describe('GET /', () => {
  test('should return Hello World message', async () => {
    const response = await request(app)
      .get('/')
      .expect(200);

    expect(response.body).toEqual({
      message: 'Hello World'
    });
  });
});

describe('404 handler', () => {
  test('should return 404 for unknown routes', async () => {
    const response = await request(app)
      .get('/unknown-route')
      .expect(404);

    expect(response.body.error.message).toBe('Not Found');
    expect(response.body.error.status).toBe(404);
  });
});

describe('Error handling', () => {
  test('should handle server errors', async () => {
    // Mock a route that throws an error for testing
    app.get('/test-error', (req, res, next) => {
      const error = new Error('Test error');
      error.status = 500;
      next(error);
    });

    const response = await request(app)
      .get('/test-error')
      .expect(500);

    expect(response.body.error.message).toBe('Test error');
    expect(response.body.error.status).toBe(500);
  });
});
