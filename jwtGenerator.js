const jwt = require('jsonwebtoken')
require('dotenv').config();

const jwtGenerator = (email) => {

    const payload = {
        user: email
    }

    return jwt.sign(payload, process.env.jwtSecret, {expiresIn:"1hr"});
     
}

module.exports=jwtGenerator;