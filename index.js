const express = require('express')
const dotenv = require('dotenv')
const app = express();
const PORT = 8000;

dotenv.config()
app.use(express.json())



app.listen(PORT, ()=>{
    console.log(`The server is running on port ${PORT}`)
});

