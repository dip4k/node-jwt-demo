const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost/nodeJwt', () => {
  console.log('mongodb connection successful');
});
