const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const app = express();
const port = 3000;
const pool = require('./db-connection');   
const jwtGenerator = require('./jwtGenerator');

app.use(bodyParser.json())
app.use(
    bodyParser.urlencoded({
        extended:true,
    })
)

app.post(['/register/mentor','register/mentee'],async(request,response) => {
    try{

        const rBody = request.body;
        let queryVals=Object.values(rBody);
        const table = "mentor";

        const saltRound = 10;
        const password = queryVals[4];
        const salt = await bcrypt.genSalt(saltRound);
        const bcryptPassword = await bcrypt.hash(password,salt);
        queryVals[4] = bcryptPassword;

        const findUser = await pool.query("SELECT * FROM " + table + " WHERE email= $1;",[queryVals[0]]);

        if(findUser.rowCount>0)
            return response.status(401).send("User already exists.");

        const newMentor = pool.query("INSERT INTO mentor VALUES($1,$2,$3,$4,$5) RETURNING *;",queryVals);
        const token = jwtGenerator(queryVals[0]);
        response.json({token});

    }catch(err){
        console.error(err.message);
    }
})

app.get(['/mentor/:id','/mentee/:id'],async(request,response) =>{
    try {
        
        const email = request.params.id;
        const table = request.url.split('/')[1];
        console.log(table);
        const user = await pool.query("SELECT * FROM " + table +" WHERE email = $1",[email]);
        //console.log(request.url.split('/'));
        if((user).rowCount==0)
        {
            return response.status(404);
        }
        else
        {
            return response.json((user).rows[0]);
        }
    } catch (err) {
        console.log(err.message);
        
    }
})

app.get('/',(request,response) => {
    response.json({info:'API running'})
})

app.listen(port,() => {
    console.log(`App running on port ${port} `);
})