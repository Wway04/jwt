const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const userModel = require('../models/User');

exports.register = async (req, res) => {
  try {
    const {username, email, password} = req.body;
    const isExist = await userModel.findUserByEmail(connection, email);
    if (isExist) {
      return res.status(400).json({message: 'User already exists'});
    }

    await userModel.createUser(connection, {username, email, password});
    res.status(201).json({message: "User registered successfully"});

  } catch (error) {
    res.status(500).json({message: "Server error"});  
  }
};
exports.login = async (req, res) => {
  try {
    const {email, password} = req.body;
    const user = await userModel.findUserByEmail(connection, email);
    if (!user) {
      return res.status(401).json({message: 'Invalid credentials'});
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({message: 'Invalid password'});
    }
    const token = jwt.sign({id: user.id}, process.env.JWT_SECRET, {expiresIn: '1h'});
    res.json({token, user:{id: user.id, email: user.email, username: user.username}});
  } catch (error) {
    res.status(500).json({message: "Server error"});
  }
};