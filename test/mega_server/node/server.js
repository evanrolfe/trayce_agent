const https = require('https');
const fs = require('fs');

// Define the options for HTTPS
const options = {
  key: fs.readFileSync('server.key'), // Path to the private key file
  cert: fs.readFileSync('server.crt') // Path to the certificate file
};

// Create an HTTPS server
https.createServer(options, (req, res) => {
  res.writeHead(200);
  res.end('Hello, world!\n');
}).listen(3003, () => {
  console.log('HTTPS Server listening on port 3003');
});
