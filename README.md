# My Hackathon Project

A minimal Node.js Express API with testing, linting, and development tools.

## Features

- **Express API** with Hello World endpoint
- **Jest** testing with coverage
- **ESLint + Prettier** for code quality
- **Basic error handling** middleware
- **Development scripts** for productivity

## Quick Start

```bash
# Install dependencies
npm install

# Run in development mode (auto-reload)
npm run dev

# Run tests
npm test

# Check code style
npm run lint

# Start production server
npm start
```

## API Endpoints

- `GET /` - Returns Hello World message

## Project Structure

```
my-hackathon-project/
├── src/
│   ├── app.js          # Express application
│   └── server.js       # Server startup
├── tests/
│   └── app.test.js     # API tests
├── .eslintrc.json      # ESLint configuration
├── .prettierrc         # Prettier configuration
├── .gitignore          # Git ignore rules
├── package.json        # Dependencies and scripts
└── README.md          # This file
```

## Development

The project includes:
- Hot reload with nodemon
- Test coverage reporting
- Automatic code formatting
- Error handling middleware
- 404 route handling

Test your setup:
```bash
curl http://localhost:3000
```

Expected response:
```json
{"message": "Hello World"}
```
