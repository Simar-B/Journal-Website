const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

//User Model
const User = require('../models/User');

//Login Page
router.get('/login', (req,res) =>res.render("login"));

//Register Page
router.get('/register', (req,res) =>res.render("register"));

//Register Handler
router.post('/register',(req, res) => {
    const {name,email,password,password2} = req.body;
    let errors = [];

    //check required fields
    if(!name || !email || !password ||!password2){
        errors.push({msg:'Please fill in all fields'});
    }

    //check password match
    if(password != password2){
        errors.push({msg:"passwords do not match"});
    }

    //check pass length
    if(password.length < 6){
        errors.push({msg:"password should be at least 6 characters"});
    }

    if(errors.length > 0){
        res.render('register',{
            errors,
            name,
            email,
            password,
            password2
        });
    }
    else{
        //validation passed
        User.findOne({email: email})
            .then(user => {
                if(user){
                    errors.push({msg:'Email is already registered'})
                    res.render('register',{
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });  
                } 
                else{
                    const newUser = new User({
                        name,
                        email,
                        password,

                    });
                    
                    // Hash password
                    bcrypt.genSalt(10, (err,salt) => 
                        bcrypt.hash(newUser.password,salt,(err,hash) => {
                            if(err) throw err;
                            // Set password to hashed
                            newUser.password = hash;
                            //Save user
                            newUser.save()
                                .then(user =>{
                                    req.flash('success_msg','You are now registered and can login');
                                    res.redirect('/users/login');
                                })
                                .catch(err => console.log(err));
                        }))

                }
            });
    }
});

//Login handle
router.post('/login', (req,res,next) => {
    passport.authenticate('local', {
        successRedirect:'/dashboard',
        failureRedirect:'/users/login',
        failureFlash:true
    })(req,res,next);


});


//Submit log handle
router.post('/submit',(req,res) => {
    //console.log(req.body);
    //console.log("submitted");
    //console.log(req.user.email);
    //console.log(req.body)
    var log = {
        title:String(req.body.title),
        body:String(req.body.log),
        date:new Date()
    };
    req.user.logs.push(log);
    req.user.save();
    //User.findOneAndUpdate({email: String(req.user.email)},{$push:{logs:String(req.log)}});
    console.log(req.user.logs);
    res.redirect("/dashboard");
})
//Logout handle
router.get('/logout',(req,res) =>{
    req.logout();
    req.flash('success_msg',"You are logged out");
    res.redirect('/users/login');
})

module.exports = router;