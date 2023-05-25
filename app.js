require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs"); /////Set EJS as view engine
app.use(express.static("public")); /////Static file in pulbic folder
app.use(bodyParser.urlencoded({ extended: true })); /////Parse the body of POST request

/////express-session
app.use(session({
  secret: process.env.SECRET_KEY, /////Secret key to encrypt the session
  resave: false, /////Flag that indicates whether to save the session again at each request
  saveUninitialized: false, /////Flag indicating whether to save an empty session or not
}));

/////Initialize passport
app.use(passport.initialize());

/////Use passport to manage session
app.use(passport.session());

/////Connect to MongoDB with Mongoose
main().catch((err) => console.log(err));
async function main() {
  await mongoose.connect(process.env.MONGODB).then(function() {
    console.log("Successfully connected to Database");
    app.listen(3000, () => {
      console.log("Server is running on port 3000.");
    });
  });
  
}

const userSchema = new mongoose.Schema({
  active: Boolean,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose); /////Plugin to make Passport easier to use with Mongoose
userSchema.plugin(findOrCreate); /////Plugin to simplify the search and creation of a user with Mongoose

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy()); /////Set to use Passport with local authentication strategy

/////Serializing the user to save it in the Passport session
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username, name: user.name });
  });
});

/////Deserializing the user from the Passport session
passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

/////Configuring the authentication strategy with Google
passport.use(
  new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALL_BACK_URL,
  }, function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }),
);

app.get("/", (req, res) => {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] }),
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  },
);

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  User.find({ "secret": { $ne: null } }).then(function (foundUsers) {
    if (req.isAuthenticated()) {
      res.render("secrets", {
        log: "Log Out",
        href: "/logout",
        userWithSecrets: foundUsers,
      });
    } else {
      res.render("secrets", {
        log: "Log in",
        href: "/login",
        userWithSecrets: foundUsers,
      });
    }
  }).catch((err) => console.log(err));
});

app.route("/submit")
  .get(function (req, res) {
    if (req.isAuthenticated()) {
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  })
  .post(function (req, res) {
    const submitedSecret = req.body.secret;
    User.findById(req.user.id).then(function (foundUser) {
      if (foundUser) {
        foundUser.secret = submitedSecret;
        foundUser.save();
        res.redirect("/secrets");
      }
    });
  });

app.post("/register", (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    },
  );
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    console.log(err);
  });
  res.redirect("/");
});

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
      res.redirect("/register")
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});


