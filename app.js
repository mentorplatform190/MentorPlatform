const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const app = express();
const port = 3000;
const pool = require('./db-connection');   
const jwtGenerator = require('./jwtGenerator');
const authorize = require('./middleware/authorization');

app.use(bodyParser.json())
app.use(
    bodyParser.urlencoded({
        extended:true,
    })
)

// Sign Up
app.post(['/register/mentor','/register/mentee'],async(request,response) => {
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
                newUser = await pool.query("INSERT INTO " + table + " (name, email, password, job_title, company, category, tags, price, experience, college, bio, profile_picture, linkedin, dates, time_slot, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *",queryVals);
            }
            const token = jwtGenerator(newUser.rows[0].id);
            response.json({token});   

        } catch (error) {
            return res.status(403).json("Something went wrong");
        }

    }catch(err){
        console.error(err.message);
        res.status(500).send("Server error");
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
            return res.status(401).json("Password or Email is Incorrect");
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

app.get('/',(request,response) => {
    response.json({info:'API running'})
})

app.listen(port,() => {
    console.log(`App running on port ${port} `);
})