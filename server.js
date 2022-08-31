const express = require('express');
const app = express();

const { pool } = require("./dbConfig");

const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('express-flash');
const passport = require("passport");

const PORT = process.env.PORT || 5000;

const initializePassport = require("./passportConfig");
initializePassport(passport);

app.set('view engine','ejs');

app.use(express.urlencoded({ extended: false}));

app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/user/register',  (req, res) => {
    res.render('register');
});

app.get('/user/login',  (req, res) => {
    res.render('login');
});
app.get('/user/dashboard', (req, res) => {
    console.log(req.isAuthenticated());
    res.render('dashboard', { user: req.user.name } );
});

app.get("/user/logout", (req, res) => {
   // req.logout();
    req.flash("success-msg","You have logged out successfully");
    res.redirect('/user/login');
  });

app.post('/user/register', async(req, res) => {
    let { name, email, password, password2 } = req.body;

    console.log({
        name,
        email,
        password,
        password2
    });

    let errors = [];

    // Check required fields
    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'Please fill in all fields' });
    }
    // Check password
    if (password !== password2) {
        errors.push({ msg: 'Passwords do not match.' });
    }
    // Check password length
    if (password.length < 6) {
        errors.push({ msg: 'Password should be at least 6 characters.' });
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
        let hashedPassword = await bcrypt.hash(password, 10);

        pool.query(
            `SELECT * FROM users WHERE email = $1`, [email], (err, results)=>{
                if(err) {
                    throw err;
                }
                console.log(results.rows);
                if(results.rows.length > 0){
                    errors.push({ msg: "Email Already Registered"});
                    res.render('register', {
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });
                }else{
                    pool.query(
                        `INSERT INTO users (name, email, password)
                        VALUES ($1, $2, $3)
                        RETURNING id, password`,[name, email, hashedPassword], (err, results)=>{
                            if(err){
                                throw err;
                            }
                            console.log(results.rows);
                            req.flash("success_msg","You are Now Registered. Please Login ");
                            res.redirect("/user/login");
                        }
                    )
                }
            }
        );
        //res.redirect('/user/login');
    }
});
app.post("/user/login",
    passport.authenticate("local", {
      successRedirect: "/user/dashboard",
      failureRedirect: "/user/login",
      failureFlash: true
    })
);


app.listen(PORT, () => {
    console.log(`Server Running on Port ${PORT}`);
});