const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const app = express();
const port = 3000;
const pool = require('./db-connection');   
const jwtGenerator = require('./jwtGenerator');
const authorize = require('./middleware/authorization');
var nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
require('dotenv').config();


app.use(bodyParser.json())
app.use(
    bodyParser.urlencoded({
        extended:true,
    })
)

// Sign Up
app.post(['/register/mentor','/register/mentee'], async(request,response) => {
    try{

        const rBody = request.body;
        let queryVals = Object.values(rBody);
        const table = request.url.split('/')[2];
        const saltRound = 10;
        const password = queryVals[2];
        const salt = await bcrypt.genSalt(saltRound);
        const bcryptPassword = await bcrypt.hash(password,salt);
        queryVals[2] = bcryptPassword;

        const findUser = await pool.query("SELECT * FROM " + table + " WHERE email = $1",[queryVals[1]]);
        
        if(findUser.rowCount>0){
            return response.status(401).json("User already exists");
        }
        try {
            var newUser = null;
            if(table === 'mentee'){
                newUser = await pool.query("INSERT INTO " + table + " (name, email, password, linkedin, reset_token) VALUES($1,$2,$3,$4,$5) RETURNING *",queryVals);
            }
            else{
                newUser = await pool.query("INSERT INTO " + table + " (name, email, password, job_title, company, category, tags, price, experience, college, bio, profile_picture, linkedin, dates, time_slot, status, reset_token) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *",queryVals);
            }
            const token = jwtGenerator(newUser.rows[0].id);
            response.json({token});   

        } catch (error) {
            return response.status(403).json("Something went wrong");
        }

    }catch(err){
        console.error(err.message);
        response.status(500).send("Server error");
    }
});

// Search User
app.get(['/mentor/:id','/mentee/:id'], authorize, async(request, response) =>{
    try {
        const id = request.params.id;
        const table = request.url.split('/')[1];
        const user = await pool.query("SELECT * FROM " + table +" WHERE id = $1",[id]);
        if((user).rowCount==0){
            return response.status(404).json("Invalid Credentials");
        }
        return response.json((user).rows[0]);
    } catch (err) {
        console.log(err.message);
    }
});

// Login 
app.post(['/login/mentor','/login/mentee'],async(request, response) =>{
    try {
        const rBody = request.body;
        let queryVals = Object.values(rBody);
        const table = request.url.split('/')[2];
        const user = await pool.query("SELECT * FROM " + table +" WHERE email = $1",[queryVals[0]]);
        if(user.rowCount==0){
            return response.status(401).json("Password or Email is Incorrect");
        }
        const validPassword = await bcrypt.compare(queryVals[1], user.rows[0].password);
        if(!validPassword){
            return response.status(401).json("Password or Email is Incorrect");
        }
        const token = jwtGenerator((user.rows[0].email));
        return response.json({ token });
    } catch (err) {
        console.log(err.message);
        return response.status(404);
    }
});

app.get("/verify", authorize, (request, response) => {
    try {
      response.json(true);
    } catch (err) {
      console.error(err.message);
      return response.status(500).send("Server error");
    }
});

app.post(['/mentor/send-email','/mentee/send-email'], async(request, response) => {
    try {
        const email = request.body.email;
        const table = request.url.split('/')[1];

        const findUser = await pool.query("SELECT * FROM " + table + " WHERE email = $1",[email]);
        var newuser = findUser.rows[0];

        if(findUser.rowCount==0){
            return response.status(401).json("Incorrect Email ID");
        }

        const payload = {
            user: {
                id: findUser.rows[0].id
            }
        }
        const token = jwt.sign(payload, process.env.RESET_PASSWORD_KEY, {expiresIn: '20m'});

        await pool.query("UPDATE " + table + " SET reset_token = $1 WHERE email = $2 RETURNING *",[token, email]);

        var transport = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'mplatform009@gmail.com',
                pass: 'mentor@12'
            }
        });
        
        var mailOptions = {
            from: 'mplatform009@gmail.com',
            to: email,
            subject: 'Testing Nodemailer in nodejs',

            html: `<h1>Hi ${newuser.name},</h1><p>${process.env.CLIENT_URL}/resetpassword/${table}/${token}</p>`
        };
        
         
        transport.sendMail(mailOptions, function(err, info){
            if(err){
                console.log(err);
            }else{
                console.log('Email Sent: '+ info.response);
            }
        });

        return response.json( {msg: "Email Sent Successfully"} );

    } catch (err) {
        console.error(err.message);
        return response.status(500).send("Server error");
    }
});

app.post(['/mentee/reset-password', '/mentor/reset-password'], async(request, response) => {
    try {
        const token = request.header("token");
        const table = request.url.split('/')[1];
        const password = request.body.password;

        const user = await pool.query("SELECT * FROM " + table + " WHERE reset_token = $1",[token]);

        if(user.rowCount===0){
            return response.json("Invalid token");
        }


        const saltRound = 10;
        const salt = await bcrypt.genSalt(saltRound);
        const bcryptPassword = await bcrypt.hash(password,salt);
        const newPassword = bcryptPassword;

        const updatedUser = await pool.query("UPDATE " + table + " SET password = $1 WHERE reset_token = $2 RETURNING *", [newPassword, token]);
        return response.json(updatedUser.rows[0]);

    } catch (err) {
        console.error(err.message);
        return response.status(500).send("Server error");
    }
});

app.get('/',(request,response) => {
    response.json( {info:'API running'} );
})

app.listen(port,() => {
    console.log(`App running on port ${port} `);
})