const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const app = express();
const port = 3000;
const pool = require('./db-connection');   
var cors = require("cors");
const jwtGenerator = require('./jwtGenerator');
const authorize = require('./middleware/authorization');
var nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
require('dotenv').config();

app.use(cors());
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
                newUser = await pool.query("INSERT INTO " + table + " (name, email, password, linkedin) VALUES($1,$2,$3,$4) RETURNING *",queryVals);
            }
            else{
                newUser = await pool.query("INSERT INTO " + table + " (name, email, password) VALUES ($1,$2,$3) RETURNING *",queryVals);
            }
            const token = jwtGenerator(newUser.rows[0].id);
            const user_data = newUser.rows[0];
            response.json({user_data, token});   

        } catch (error) {
            return response.status(403).json("Something went wrong");
        }

    }catch(err){
        console.error(err.message);
        response.status(500).send("Server error");
    }
});

app.post('/mentor/update', async(request, response) => {
    try {
        const id = request.header("id");
        const user_id = await pool.query("SELECT * from mentor WHERE id = $1",[id]);
        if(user_id.rowCount===0){
            console.log("Invalid ID");
            return response.json("Invalid Credential");
        }
        const rBody = request.body;
        try {
            const user = await pool.query("UPDATE mentor SET job_title = $1, company = $2, category = $3, tags = $4, price = $5, experience = $6, college = $7, bio = $8, mobile_number = $9, profile_picture = $10, linkedin = $11, date_time = $12 WHERE id = $13 RETURNING *",
            [rBody.job_title, rBody.company, rBody.category, rBody.tags, rBody.price, rBody.experience, rBody.college, rBody.bio, rBody.mobile_number, rBody.profile_picture, rBody.linkedin, rBody.date_time, id]);
            return response.json(user.rows[0]);   
        } catch (err) {
            console.log(err.message);
            response.send("Issue with update query");
        }

    } catch (err) {
        console.log(err.message);
        response.status(500).send("Server Error");
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
        response.status(500).send("Server error");
    }
});

// all mentor information

app.get('/all/mentor', async(request, response) => {
    try {
        const allUser = await pool.query("SELECT * FROM mentor");
        return response.json(allUser.rows);   

    } catch (err) {
        console.log(err.message);
        response.status(500).send("Server error");
    }
});

// Login 
app.post(['/login/mentor','/login/mentee'], async(request, response) =>{
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
        const user_data = user.rows[0];
        return response.json({ user_data, token });
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

// Call API(To Write Data in DB and send mail to mentor about the request)
app.post('/call', async(request, response) => {
    try {
    const { mentor_id, mentee_id, dates_time, booking_status } = request.body
    await pool.query('INSERT INTO book_call (mentor_id, mentee_id, dates_time, booking_status) VALUES ($1, $2, $3, $4)', [mentor_id, mentee_id, dates_time, booking_status], (error, results) => {
      if (error) {
        throw error
      }
      response.status(201).json(`Slot Booked`)
    })
    const mentorId = request.body.mentor_id;
    const user = await pool.query("SELECT * FROM mentor WHERE id = $1",[mentor_id]);
    var mentorMail =  user.rows[0].email;
    var mentorName =  user.rows[0].name;
    var transport = nodemailer.createTransport({
       service: 'gmail',
       auth: {
           user: 'mplatform009@gmail.com',
           pass: 'mentor@12'
       }
   });
   var mailOptions = {
    from: 'mplatform009@gmail.com',
    to: mentorMail,
    subject: 'Confirm the Session',
 
    html: `<p>Hi ${mentorName},</p><p>Please confirm the request by visiting Mentee Request page on website</p>`
};
 
   transport.sendMail(mailOptions, function(err, info){
    if(err){
        console.log(err);
    }else{
        console.log('Email Sent: '+ info.response);
    }
});
    } catch (err) {
        console.error(err.message);
        return response.status(500).send('email not send');
    }
});
 
 
///API to confirm the mentee request by Mentor
 
app.get('/menteeRequest/:id', async(request, response) => {
    try {
    const id = request.params.id;
    console.log(id);
    const user = await pool.query("SELECT * FROM book_call WHERE id = $1",[id]);
    const menteeId = user.rows[0].mentee_id;
    const mentee = await pool.query("SELECT * FROM mentee WHERE id = $1",[menteeId]);
    var menteeMail =  mentee.rows[0].email;
    var menteeName =  mentee.rows[0].name;
    var transport = nodemailer.createTransport({
       service: 'gmail',
       auth: {
           user: 'mplatform009@gmail.com',
           pass: 'mentor@12'
       }
   });
   var mailOptions = {
    from: 'mplatform009@gmail.com',
    to: menteeMail,
    subject: 'Session Confirmed',
 
    html: `<p>Hi ${menteeName},</p><p>Your session has been Confirmed.</p><p>We will send you the call Link soon</p>`
};
 
   transport.sendMail(mailOptions, function(err, info){
    if(err){
        console.log(err);
    }else{
        console.log('Email Sent: '+ info.response);
    }
    });
     return response.json("mail send to "+menteeName);

    } catch (err) {
        console.error(err.message);
        return response.status(500).send('email not send');
    }
});

app.get('/',(request,response) => {
    response.json( {info:'API running'} );
})

app.listen(port,() => {
    console.log(`App running on port ${port} `);
})