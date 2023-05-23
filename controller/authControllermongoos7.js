//Code for mongoose 7.0

const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('../config');
const User = require('../model/userSchema');

router.use(bodyParser.urlencoded({extended:true}));
router.use(bodyParser.json());

router.get('/users', async(req,res) => {
    let output = await User.find({})
    res.send(output)
})


router.post('/register', async(req,res)=>{

    //encrypt pass
    let hashpass = bcrypt.hashSync(req.body.password,8)
    let response =await User.create({
        name: req.body.name,
        email: req.body.email,
        password: hashpass,
        phone: req.body.phone,
        role: req.body.role?req.body.role:'User',
    })
    res.status(200).send('Registration Successful')
})

//login
router.post('/login', async(req,res)=>{
    let user = await User.findOne({
        email:req.body.email
    });
    //wrong pass
    if(!user) res.send({auth:false, token:'No user found, register first'});
    else{
        const passValid = bcrypt.compareSync(req.body.password, user.password);
        if(!passValid) res.send({auth:false, token:"Password not valid"});

        // correct pass
        let token = jwt.sign({id:user._id}, config.secret,{expiresIn:86000})
        res.send({auth:true, token:token})
    }
})

//getting user info
router.get('/userinfo', async (req,res)=>{
    let token = req.headers['access-token'];
    if(!token) res.send({auth:false, token:"No Token given"});
    //jwt verification
    await jwt.verify(token,config.secret,async(err,user)=>{
        if(err) res.send({auth:false, token:"Inavlid token"})
        let output = await User.findById(user.id);
        res.send(output)
    })
})


module.exports = router;