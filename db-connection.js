const Pool = require('pg').Pool
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'mentor_platform',
  password: 'postgres',
  port: 5432,
})

module.exports=pool;