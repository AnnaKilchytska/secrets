//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy = require('passport-facebook');
//This was to use encryption
// const encrypt = require('mongoose-encryption');

//hashing
// const md5 = require('md5');

// const bcrypt = require('bcrypt');
// const saltRounds = 10;

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
//1.Initialize a session below other app.use
app.use(session({
  secret: 'This is our little secret',
  resave: false,
  saveUninitialized: false
}))
//2.Initialize passport
app.use(passport.initialize());
//3.to tell our app to use passport to set up a session
app.use(passport.session());

// mongoose.connect('mongodb://localhost:27017/userDB', {
//   useNewUrlParser: true
// });
mongoose.connect("mongodb+srv://admin-anna:test123@cluster0.9t9cy.mongodb.net/userDB?retryWrites=true&w=majority", {
  useNewUrlParser: true
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//This was the next step of using encryption
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });

const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user)
  })
})

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      facebookId: profile.id,
      username: profile.displayName
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

app.get('/', (req, res) => {
  res.render('home');
});

app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile']
  }));

app.get('/auth/google/secrets',
  passport.authenticate('google', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get('/auth/facebook',
  passport.authenticate('facebook', {
    scope: ['public_profile']
  }));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.get('/secrets', (req, res) => {

  User.find({'secret': {$ne: null}}, (err, foundUsers) => {
    if (err) console.log(err);
    if (!err && foundUsers) res.render('secrets', {usersWithSecrets: foundUsers})
  })

})

app.get('/submit', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('submit');
  } else {
    res.redirect('/login');
  }
})

app.post('/submit', (req, res) => {
  const submittedSecret = req.body.secret;
  console.log(req.user);

  User.findById(req.user.id, (err, foundUser) => {
    if (err) console.log(err);
    if (!err && foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(() => {
          res.redirect('/secrets');
        })
    }
  })
})

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
})

app.post('/register', (req, res) => {

  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   // Store hash in your password DB.
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //   newUser.save((err) => {
  //     if (err) console.log(err);
  //     if (!err) res.render('secrets');
  //   });
  // });

  User.register({
    username: req.body.username
  }, req.body.password, (err, user) => {
    if (err) {
      console.log(err);
      res.redirect('/register');
    } else {
      passport.authenticate('local')(req, res, () => {
        res.redirect('/secrets');
      })
    }
  })


});

app.post('/login', (req, res) => {
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({
  //   email: username
  // }, (err, foundUser) => {
  //   if (err) console.log(err);
  //   if (!err) {
  //     if (foundUser) {
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //         if (result === true) res.render('secrets');
  //       });
  //
  //     }
  //   }
  // })

  const user = new User({
    username: req.body.username,
    password: req.body.password
  })

  req.login(user, (err) => {
    if (err) console.log(err);
    if (!err) passport.authenticate('local')(req, res, () => {
      res.redirect('/secrets')
    })
  })
})









app.listen(3000, () => {
  console.log('Server has started on port 3000');
})
