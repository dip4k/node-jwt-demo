const express = require('express');

let app = express();
require('./db');
let AuthController = require('./auth/AuthController');
let UserController = require('./user/UserController');

app.use('/api/auth', AuthController);

app.use('/users', UserController);

module.exports = app;
