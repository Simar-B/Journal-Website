const express = require('express');
const router = express.Router();
const {ensureAuthenticated} = require('../config/auth');

//Welcome page
router.get('/', (req,res) =>res.render("Welcome"));

//Dashboard
router.get('/dashboard',ensureAuthenticated, (req,res) =>
res.render("dashboard",{
    name: req.user.name,
    logs: req.user.logs
}));
module.exports = router;