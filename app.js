//jshint esversion:6
//dot env is used whenever the .env file is to be read from 
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const app = express();
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

// const bcrypt = require('bcrypt'); this is for salted hashing using bcrypt
// const saltRounds = 10;
// const md5 = require('md5'); this is a hashing encryption: this is just mere hashing using md5
// const encrypt = require('mongoose-encryption');

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended:true}));

app.use(express.static('public'));

app.use(session({
    secret: 'thisisourlittlesecret',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb+srv://admin-kizzy1:kizzy123@reproof-rs58r.mongodb.net/SecretsDB', {useNewUrlParser: true, useUnifiedTopology:true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
    facebookId: String,
    googleId: String,
    email: String,
    password: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);

userSchema.plugin(findOrCreate);

//this is a plugin to enable encryption in the database and it doesnt need to be called during decryption since it decrypts automatically 
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});

const User = mongoose.model('User', userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/secrets', 
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
}, function(accessToken, refreshToken, profile, cb){
    console.log(profile.id);
    User.findOrCreate({googleId: profile.id}, function(err, user){
        return cb(err, user);
    })
}))

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/', function(req, res){
    res.render('home');
});

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
passport.authenticate('facebook', { failureRedirect: '/login' }),
function(req, res) {
// Successful authentication, redirect home.
res.redirect('/secrets');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
passport.authenticate('google', { failureRedirect: '/login' }),
function(req, res) {
res.redirect('/secrets');
});

app.route('/login') 
    .get(function(req, res){
        res.render('login');
    })
    .post(function(req, res){

        const user = new User({
            username: req.body.username,
            password: req.body.password
        })
        
        req.login(user, function(err){
            if(err){
                console.log(err);
                res.redirect('/login')
            }else{
                 // this authenticates the user and creates a cookie
                passport.authenticate('local')(req, res, function(){
                    res.redirect('secrets')
                }) 
            }
        })

    });

app.get('/submit', function(req, res){
    if(req.isAuthenticated()){
        res.render('submit');
    }else{
        res.redirect('/login')
    }
})

app.post('/submit', function(req, res){
    const secret = req.body.secret;

    User.findOneAndUpdate({_id: req.user.id}, {secret: secret}, function(err){
        if(err){
            console.log(err);
        }else{
            res.redirect('/submit')
        }
    })
})

app.route('/register')
    .get(function(req, res){
        res.render('register');
    })
    .post(function(req, res){
        const username = req.body.username;
        const password = req.body.password;
        
        User.register({username: username, active: true}, password, function(err, user){
            if(err){
                console.log(err);
                res.redirect('/register');
            }else{
                // this authenticates the user and creates a cookie
                passport.authenticate('local')(req, res, function(){
                    // the redirect is used to go through the step of checking authentication in the secret route
                    res.redirect('/secrets');
                });
            }
            
        });
       
    });

app.get('/secrets', function(req, res){
    
    User.find({}, function(err, user){
        if(err){
            console.log(err);
        }else{
            res.render('secrets', {users: user})
        }
    })
    
})

app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/');
})

app.listen(3000, function(){
    console.log('Starting server at port 3000.....');
});