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
            await pool.query("UPDATE mentor SET status = $1 WHERE id = $2",[true,id]);
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
app.get(['/mentor/:id','/mentee/:id'], async(request, response) =>{
    try {
        const id = request.params.id;
        const table = request.url.split('/')[1];
        const user = await pool.query("SELECT * FROM " + table +" WHERE id = $1",[id]);
        if((user).rowCount==0){
            return response.status(404).json("Invalid Credentials");
        }
        const allSlots = user.rows[0].date_time;
        var booked_slot = null;
        if(table === 'mentor'){
            const book_info = await pool.query("SELECT dates_time FROM book_call WHERE mentor_id = $1",[id]);
            booked_slot = book_info.rows;
            for(let i of booked_slot){
                var x = booked_slot[i].dates_time;
                console.log(x);
                // var index = allSlots.indexOf(booked_slot[i].dates_time);
                // console.log(index);
                allSlots.splice(index, 1);
            }
            // console.log(booked_slot[1].dates_time);
        }
        const user_data = user.rows[0];
        return response.json( {user_data, booked_slot} );
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
 
    html: `<h3>Hi ${mentorName},</h3><p>Please confirm the request by logging into your MyMentor account.</p>`
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
    const updateStatus = await pool.query("UPDATE book_call SET booking_status='confirm' WHERE id = $1",[id]);
    if(updateStatus.rowCount==0){
        return response.status(401).json("Booking Id does not Exist");
    }
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
 
    html: `<h3>Hi ${menteeName},</h3><p>Your session has been Confirmed.</p><h4>We will send you the Invite Link soon.</h4>`
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

app.get('/mentorinfo/:id', async(request, response) => {
    try {
    const id = request.params.id;
    const user = await pool.query("SELECT * FROM book_call WHERE mentor_id = $1 AND booking_status='pending'",[id]);
    const size = user.rows.length;
    var callData = [];
    const mentor = await pool.query("SELECT * FROM mentor WHERE id = $1",[id]);
    for(var i=0;i<size;i++){
        const menteeId = user.rows[i].mentee_id;
        const mentee = await pool.query("SELECT * FROM mentee WHERE id = $1",[menteeId]);
        
         callData[i] = {
            "call_id": user.rows[i].id,
            "mentor_id": user.rows[i].mentor_id,
            "mentee_name": mentee.rows[0].name,
            "mentor_name": mentor.rows[0].name,
            "call_time": user.rows[i].dates_time,
            "mentor_email": mentor.rows[0].email,
            "mentee_email": mentee.rows[0].email
        }
        console.log(user.rows[i].dates_time);
    }
     return response.send(callData);

    } catch (err) {
        console.error(err.message);
        return response.status(500).send('You dont have permission');
    }
});

// Google Calendar Events Book
app.post('/events', (req, res) => {

    const book_date = req.body.date;
    const mentor_name = req.body.mentor_name;
    const mentee_name = req.body.mentee_name;
    const mentor_email = req.body.mentor_email;
    const mentee_email = req.body.mentee_email;

    const { google } = require('googleapis')
    // Require oAuth2 from our google instance.
    const { OAuth2 } = google.auth
  
    // Create a new instance of oAuth and set our Client ID & Client Secret.
    const oAuth2Client = new OAuth2(process.env.CLIENT_ID, process.env.CLIENT_SECRET)
  
    // Call the setCredentials method on our oAuth2Client instance and set our refresh token.
    oAuth2Client.setCredentials({
      refresh_token: process.env.REFRESH_TOKEN,
    })
  
    // Create a new calender instance.
    const calendar = google.calendar({ version: 'v3', auth: oAuth2Client })
  
    // Create a new event start date instance for temp uses in our calendar.
    const TIMEOFFSET = '+05:30';

// Get date-time string for calender
    const dateTimeForCalander = () => {

        let date = new Date(book_date);

        let year = date.getFullYear();
        let month = date.getMonth() + 1;
        if (month < 10) {
            month = `0${month}`;
        }
        let day = date.getDate();
        if (day < 10) {
            day = `0${day}`;
        }
        let hour = date.getHours();
        if (hour < 10) {
            hour = `0${hour}`;
        }
        let minute = date.getMinutes();
        if (minute < 10) {
            minute = `0${minute}`;
        }

        let newDateTime = `${year}-${month}-${day}T${hour}:${minute}:00.000${TIMEOFFSET}`;

        let startDate = new Date(Date.parse(newDateTime));
        // Delay in end time is 1
        let endDate = new Date(new Date(startDate).setHours(startDate.getHours()+1));

        return {
            'start': startDate,
            'end': endDate
        }
    };

    const insertEvent = async (event) => {  

        try {
            let response = await calendar.events.insert({   
                calendarId: process.env.CALENDAR_ID,
                resource: event,
                sendNotifications: true,
                conferenceDataVersion: 1,
            });
        
            if (response['status'] == 200 && response['statusText'] === 'OK') {
                return 1;
            } else {
                return 0;
            }
        } catch (error) {
            console.log(`Error at insertEvent --> ${error}`);
            return 0;
        }
    };
    let dateTime = dateTimeForCalander();

    const event = {
      summary: 'My Mentor Booking',
      description: `This is regarding the booking between ${mentee_name} and ${mentor_name} made through MyMentor Platform`,
      colorId: 1,
      start: {
        dateTime: dateTime['start'],
        timeZone: 'Asia/Kolkata',
      },
      end: {
        dateTime: dateTime['end'],
        timeZone: 'Asia/Kolkata',
      },
      attendees: [
        {email: mentee_email},
        {email:  mentor_email},
      ],
      conferenceData: {
        createRequest: {
          conferenceSolutionKey: {
            type: "hangoutsMeet",
          },    
          requestId: "7qxalsvy0e",
        }
      },
    }
    console.log(dateTime['start']);
    console.log(dateTime['start']);

    insertEvent(event)
    .then((res) => {
        console.log(res);
    })
    .catch((err) => {
        console.log(err);
    });  
}); 

app.get('/',(request,response) => {
    response.json( {info:'API running'} );
})

app.listen(port,() => {
    console.log(`App running on port ${port} `);
})