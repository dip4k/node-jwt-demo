const router = require('express').Router();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const keys = require('../secret/keys');
const User = require('../user/User');
const VerifyToken = require('./VerifyToken');

router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());

// register
router.post('/register', (req, res) => {
  let hashedPassword = bcrypt.hashSync(req.body.password, 8);
  User.create(
    {
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword
    },
    (err, user) => {
      if (err) {
        return res.status(500).send('There was a problem registering the user.');
      }
      /* eslint no-underscore-dangle:0 */
      // create a token
      let token = jwt.sign({ id: user._id }, keys.secret, {
        expiresIn: 86400 // expires in 24 hours 24*60*60
      });
      res.status(200).send({ auth: true, token });
    }
  );
});

router.get('/me', VerifyToken, (req, res, next) => {
  let token = req.headers['x-access-token'];
  if (!token) {
    return res.status(401).send({ auth: false, message: 'No token provided.' });
  }

  jwt.verify(token, keys.secret, (err, decoded) => {
    if (err) {
      return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
    }

    User.findById(
      decoded.id,
      { password: 0 }, // projection
      (error, user) => {
        if (error) {
          return res.status(500).send('There was a problem finding the user.');
        }
        if (!user) {
          return res.status(404).send('No user found.');
        }
        res.status(200).send(user);
      }
    );
  });
});

// login
router.post('/login', (req, res) => {
  User.findOne({ email: req.body.email }, (err, user) => {
    if (err) {
      return res.status(500).send('Error on the server.');
    }
    if (!user) {
      return res.status(404).send('No user found.');
    }
    let passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
    if (!passwordIsValid) {
      return res.status(401).send({ auth: false, token: null });
    }
    let token = jwt.sign({ id: user._id }, keys.secret, {
      expiresIn: 86400 // expires in 24 hours
    });
    res.status(200).send({ auth: true, token });
  });
});

// logout
router.get('/logout', (req, res) => {
  res.status(200).send({ auth: false, token: null });
});

module.exports = router;
