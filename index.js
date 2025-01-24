const express = require('express')
const bodyParser = require('body-parser')
const dotenv = require('dotenv')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
dotenv.config()
app.use(bodyParser.json())
app.use(express.json())

const PORT = process.env.PORT || 5000;
app.listen(PORT, (req, res) => {
  console.log(`Currently running port is ${PORT}`)
})
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB Connected')).catch(err => console.log(err));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ['admin', 'staff', "agent"], default: 'agent' }
})

const File = mongoose.model("FileList", userSchema)


app.post('/user-add', (req, res) => {
    const user = req.body.data;
    res.send(`Hi ${user.name} Welcome to Express.js`)
})

app.post('/register', async (req, res) => {
    try{
      const {username , password, role} = req.body;
     
      const exitingUser = await File.findOne({username});

      if(exitingUser){
        return res.status(400).json({message : "user already Exits"})
      }

      const hasPassword = await bcrypt.hash(password , 10)

      const user = new File({
        username , password : hasPassword, role
      })

      await user.save();

      return res.status(200).json({message : "Registerd Successfully"})

    }catch(error){
    }
    
})

app.post('/login', async (req, res) => {
  try {
    //get credintials from user
    const { username, password } = req.body

    const user = await File.findOne({ username })

    //check if user is valid

    if (!user) return res.status(400).json({ message: "Invalid credintials" })

    //check user password and DB password matches
    const isPasswordValid = await bcrypt.compare(password, user.password)

    if (!isPasswordValid) return res.status(400).json({ message: "Invalid password" })

    //generate JWT token
 
    const token = jwt.sign(
      {
        id: user._id,
        role: user.role
      },
      process.env.JWT_TOKEN,
      {
       expiresIn : '1h'
      }
    )

    res.json({message: "Login Successfully", token})


  } catch (error) {
    res.status(500).json({ message: "Error Login", error })
  }
})

//middleware for auth

const authenticate = (req, res, next) => {

  const token = req.headers.authorization?.split(' ')[1]
  console.log(token)

  if(!token) return res.status(401).json({message : "Access Denied No Token provided"})
 
  try {
    const decoded = jwt.verify(token, process.env.JWT_TOKEN)

    req.user = decoded

    next();

  } catch (error) {
    
    res.status(403).json({
      message : "Invalid Token", error
    })
  }

}

//authorize the valid role 
const authorize = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied' });
  }
  next();
};


//protected route for Admin
app.get('/protected', authenticate , authorize(['admin']), (req, res) => {
  res.json(
    {
      message: "Welcome to the Protected route",
      user: req.user
    })
})

app.get('/user',(req, res) => {
   res.json({message : "Welcome to user route", user : req.user})
})

//get the User list passed by filter
app.post('/user/list', async (req, res) => {
  try {
    const filter = req.body.data;
    const userList = await File.find().select(filter)
    res.status(200).json(userList)
  } catch (error) {
    res.status(500).json({message : 'Error in Api', error})
  }
})

app.get('/', (req, res) => {
    res.send("Welcome to Dan express.js")
})

