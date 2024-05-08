/*
* COMP2537 Assignment 2
* Calvin Lee, Set 2B
*/

// Requires and additional setup
require("./utils.js");
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const saltRounds = 12;

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({extended: false}));
app.use(express.static(__dirname + "/public"));
app.set('view engine', 'ejs');

// Databsase secrets, .env imports, mongo things
const expireTime = 1000 * 60 * 60;    // 1000 ms/s * 60 s/min * 60 min/hr
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const MongoClient = require("mongodb").MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true`;
var database = new MongoClient(atlasURI);
const userCollection = database.db(mongodb_database).collection('users');
var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
});

// Cookies
app.use(session({ 
  secret: node_session_secret,
  store: mongoStore, //default is memory store 
  saveUninitialized: false, 
  resave: true
}));

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Root/index page

app.use('/', setupHeader);
app.get('/home', (req, res) => {
  res.redirect('/');
});
app.get('/', (req, res) => {
  res.render("home", { loggedIn: req.session.authenticated, name: req.session.name })
});

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Signup page and submission

app.get('/signup', (req, res) => {
  res.render("signup");
});

app.post('/signupSubmit', async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var pw = req.body.password;   // maybe change password to require min length?

  const schema = Joi.object({
    name:   Joi.string().alphanum().max(20).required(),
    email:  Joi.string().email({minDomainSegments: 2, tlds: { allow: ['com', 'org', 'net']}}).required(),
    pw:     Joi.string().max(20).required()
  });

  const validationResult = schema.validate({name, email, pw});

  // if name is empty
  if (validationResult.error != null) {
    if (!name) {
      res.render("signupFail", {field: "Name"});
      return;
    }
    else if (!email) {
      res.render("signupFail", {field: "Email"});
      return;
    }
    else if (!pw) {
      res.render("signupFail", {field: "Password"});
      return;
    }
  }
  // check if email already exists in the database
  const result = await userCollection.countDocuments({email: email});

  // a user document with that email exists, sign up failed
  if (result > 0) {
    res.render("userExists");
    return;
  }

  // add name, email. and bcrypted hashed password as user to db
  // then create a session and redirect user to /members page
  var hashedPw = await bcrypt.hash(pw, saltRounds);
  await userCollection.insertOne({username: name, email: email, password: hashedPw, role: "user"});

  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;
  res.redirect("/members");
  return;
});

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Login page and submission

app.get('/login', (req, res) => {
  res.render("login");
});

app.post('/loginSubmit', async (req, res) => {
  // check user against mongo db, use Joi to validate input
  var email = req.body.email;
  var pw = req.body.password;

  const schema = Joi.object({
    email:  Joi.string().email({minDomainSegments: 2, tlds:{ allow: ['com', 'org', 'net', 'ca']}}).required(),
    pw:     Joi.string().max(20).required()
  });
  const validationResult = schema.validate({email, pw});
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  const result = await userCollection.find({email: email}).project({username: 1, password: 1, role: 1}).toArray();

  // check if email is found
	if (result.length != 1) {
    res.render("emailNotFound");
	}
  // if email is found, check that the pw matches the bcrypted pw
	else if (await bcrypt.compare(pw, result[0].password)) {
		// correct password, store user's name in session, log the user in and redirect to /members
		req.session.authenticated = true;
		req.session.name = result[0].username;
    req.session.role = result[0].role;
		req.session.cookie.maxAge = expireTime;
		res.redirect("/members");
		return;
	}
	else {
		// incorrect password
    res.render("wrongPw");
	}
});

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Members page

app.get('/members', (req, res) => {
  // if user has a valid session, say hello and name of user
  if (req.session.authenticated) {
    // display random image from selection of 3 images, stored in /public folder of server
    var rnd = Math.floor(Math.random() * 3) + 1;
    var name = req.session.name;
    res.render("members", { name: name });
  }
  // if user has no session, redirect to home page
  else {
    res.redirect(`/`);
    return;
  }
});

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Admin page

app.get('/admin', async (req, res) => {
  // if they are not logged in, redirect to login page
  if (!req.session.authenticated) {
    res.redirect("/login");
    return;
  }

  // if the user is not an admin, display error message with status code 403
  if (req.session.role == "user") {
    res.status(403);
    res.render("admin", { role: "user" });
    return;
  }
  // if the user is an admin, show all users and their type
  // for each user, provide a link to promote them to admin or demote them to regular user
  else {
    const users = await userCollection.find().project({username: 1, email: 1, role: 1}).toArray();
    var usrEmail = req.query.email;
    var action = req.query.action;

    // check for a valid action (promote/demote), email not empty, and user is admin
    if (!usrEmail || !action || req.session.role != "admin") {
      res.render("admin", { role: "admin", users: users });
      return;
    }

    const userToUpdate = await userCollection.find({ email: usrEmail}).project({username: 1, role: 1}).toArray();

    if (userToUpdate.length == 0) { 
      res.render("/admin", { role: "admin", users: users });
      return;
    }
  
    // if user is already admin, let the user know
    if (action == "promote") {
      if (userToUpdate[0].role == "admin") {
        console.log("That person is already an admin.");
        res.redirect("/admin");
        return;
      }
      else {
        await userCollection.updateOne({email: usrEmail}, {$set: {role: "admin"}});
        console.log("Successfully promoted " + userToUpdate[0].username + " to admin.");
        res.redirect("/admin");
        return;
      }
    }
    else { // if action is demote
      if (userToUpdate[0].role == "user") {
        console.log("That person is already a user.");
        res.redirect("/admin");
        return;
      }
      else {
        await userCollection.updateOne({email: usrEmail}, {$set: {role: "user"}});
        console.log("Successfully demoted " + userToUpdate[0].username + " to user.");
        res.redirect("/admin");
        return;
      }
    }
  }

});

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// User log-out

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect(`/`);
  return;
});

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Handle non-existent pages (404)

app.get('*', (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Helper functions

var nav = [
  ["Home", "/"],
  ["Members", "/members"]
];

function setupHeader(req, res, next) {
  app.locals.navLinks = nav;
  let str = req.originalUrl.split('/');
  app.locals.currentUrl = str[1];
  next();
}