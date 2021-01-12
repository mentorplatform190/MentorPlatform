const jwt = require('jsonwebtoken');
require('dotenv').config();

module.exports = async(request, response, next) => {
    try {
        const jwtToken = request.header("token");

        if(!jwtToken){
            return response.status(403).json( {msg: "Authorization denied"} );
        }
        const payload = jwt.verify(jwtToken, process.env.jwtSecret);
        request.user = payload.user;
        next();

    } catch (err) {
        console.error(err.message);
        return response.status(403).json( {msg: "Token is not valid"} );    
    }
};