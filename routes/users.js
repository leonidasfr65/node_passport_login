const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
// const md5 = require('md5');

// Load User model
const User = require('../models/User');
const { ensureAuthenticated, forwardAuthenticated } = require('../config/auth');
const mysql = require('mysql');

// Config MYSQL
const dbMysql = mysql.createConnection({
  host: "152.228.175.158",
  database: 'dreamagency_elevatedb',
  user: "dreamagency_elevatedb",
  password: "XThIeOMZ9Wo1"
});

// Login Page
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'));

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'));

// Register
router.post('/register', (req, res) => {
  const { name, email, password, password2 } = req.body;
  let errors = [];

  if (!name || !email || !password || !password2) {
    errors.push({ msg: 'Veuillez saisir tous les champs' });
  }

  if (password != password2) {
    errors.push({ msg: 'Les mots de passe ne correspondent pas' });
  }

  if (password.length < 6) {
    errors.push({ msg: 'Le mot de passe doit être au moins de 6 caractères' });
  }

  if (errors.length > 0) {
    res.render('register', {
      errors,
      name,
      email,
      password,
      password2
    });
  } else {
    User.findOne({ email: email }).then(user => {
      if (user) {
        errors.push({ msg: 'L\'email existe déjà' });
        res.render('register', {
          errors,
          name,
          email,
          password,
          password2
        });
      } else {
        const newUser = new User({
          name,
          email,
          password
        });

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser
              .save()
              .then(user => {
                dbMysql.connect(function (err) {
                  if (err) throw err;
                  console.log("Connecté à la base de données MySQL!");
                  var sql = 'INSERT INTO users (name, password, email) VALUES ? ';
                  let values = [
                    [newUser.name, newUser.password, newUser.email]
                  ];
                  dbMysql.query(sql, [values], function (err, result) {
                    if (err) throw err;
                    console.log("Base de données créée !");
                  });
                });
                req.flash(
                  'success_msg',
                  'Vous êtes maintenant inscrit et vous pouvez vous connecter'
                );
                res.redirect('/users/login');
              })
              .catch(err => console.log(err));
          }); /// End Bcrypt Hash
        }); // End Bcrypt
      }
    });
  }
});

// Login
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/users/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
  })(req, res, next);
});

// Logout
router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'Vous êtes déconnecté');
  res.redirect('/users/login');
});

// Dashboard User
router.get('/dashboard', ensureAuthenticated, (req, res) =>
  res.render('user/dashboard', {
    user: req.user,
    layout: 'user_layout'
  })
);

// Products list
router.get('/products', ensureAuthenticated, (req, res) =>
  res.render('user/products', {
    user: req.user,
    layout: 'user_layout'
  })
);


// User Infos
router.get('/infos', ensureAuthenticated, (req, res) =>
  res.render('user/user_infos', {
    user: req.user,
    layout: 'user_layout'
  })
);

module.exports = router;