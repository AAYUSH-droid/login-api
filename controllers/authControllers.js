const User = require('../model/authModel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const randomstring = require('randomstring');
const config = require('../config/config');

require('dotenv').config();
const sgMail = require('@sendgrid/mail');
const API_KEY = process.env.SENDMAIL_API_KEY;
// console.log('apikey', API_KEY);
sgMail.setApiKey(API_KEY);

const sendMail = (name, email, token) => {
  return new Promise((resolve, reject) => {
    try {
      const msg = {
        to: email,
        from: 'shaishav.mahaseth@acumensa.co',
        subject: 'Reset your password',
        html: '<p> Rest your password here ' + email + '</p>',
      };
      sgMail
        .sendMultiple(msg)
        .then((msg) => {
          resolve(msg);
        })
        .catch((err) => {
          reject(err);
        });
    } catch (err) {
      reject(err);
    }
  });
};

const maxAge = 3 * 24 * 60 * 60;
const createToken = (id) => {
  return jwt.sign({ id }, ' super secret key', {
    expiresIn: maxAge,
  });
};

const handleErrors = (err) => {
  let errors = { email: '', password: '' };

  console.log(err);
  if (err.message === 'incorrect email') {
    errors.email = 'That email is not registered';
  }

  if (err.message === 'incorrect password') {
    errors.password = 'That password is incorrect';
  }

  if (err.code === 11000) {
    errors.email = 'Email is already registered';
    return errors;
  }

  if (err.message.includes('Users validation failed')) {
    Object.values(err.errors).forEach(({ properties }) => {
      errors[properties.path] = properties.message;
    });
  }

  return errors;
};
//hash the new password
const securePassword = async (password) => {
  try {
    const passHash = await bcrypt.hash(password, 10);
    return passHash;
  } catch (error) {
    res.status(400).send(error.message);
  }
};
module.exports.register = async (req, res, next) => {
  try {
    const { email, password, mobileNo, address } = req.body;
    const user = await User.create({ email, password, mobileNo, address });
    const token = createToken(user._id);

    res.cookie('jwt', token, {
      withCredentials: true,
      httpOnly: false,
      maxAge: maxAge * 1000,
    });

    res.status(201).json({ user: user._id, created: true });
  } catch (err) {
    console.log(err);
    const errors = handleErrors(err);
    res.json({ errors, created: false });
  }
};

module.exports.login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.login(email, password);
    const token = createToken(user._id);
    res.cookie('jwt', token, { httpOnly: false, maxAge: maxAge * 1000 });
    res.status(200).json({ user: user._id, status: true });
  } catch (err) {
    const errors = handleErrors(err);
    res.json({ errors, status: false });
  }
};

module.exports.forget_password = async (req, res) => {
  try {
    const email = req.body.email;
    const userData = await User.findOne({ email: email });

    if (userData) {
      const randomString = randomstring.generate();
      const data = await User.updateOne(
        { email: email },
        { $set: { token: randomString } }
      );
      sendMail(userData.name, userData.email, randomString);
      res.status(200).send({
        success: true,
        msg: 'Check your inbox and reset your password',
      });
    } else {
      res.status(200).send({ success: true, msg: 'This email does not exist' });
    }
  } catch (err) {
    res.status(400).send({ success: false, msg: err.message });
  }
};

//abhi krna h shi
const comparePassword = async (plainPassword, hashedPassword) => {
  try {
    const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
    // console.log(plainPassword, hashedPassword);
    return isMatch;
  } catch (error) {
    throw new Error('Error comparing passwords');
  }
};

module.exports.reset_password = async (req, res) => {
  try {
    const { email, oldPassword, newPassword } = req.body;
    const user = await User.findOne({ email });

    // if (user) {
    //   // Check if the old password matches the stored password
    //   const isOldPasswordValid = await comparePassword(
    //     oldPassword,
    //     user.password
    //   );
    //   // console.log(isOldPasswordValid);

    if (user) {
      // Update the password with the new password
      const hashedPassword = await securePassword(newPassword);
      user.password = hashedPassword;
      // user.token = ''; // Assuming you want to clear the token

      // Save the updated user in the database
      const updatedUser = await user.save();

      res.status(200).send({
        success: true,
        msg: 'User password has been reset',
        data: updatedUser,
      });
      // else {
      //   res
      //     .status(401)
      //     .send({ success: false, msg: 'Old password is incorrect' });
      // }
    } else {
      res.status(404).send({ success: false, msg: 'User not found' });
    }
  } catch (err) {
    res.status(500).send({ success: false, msg: err.message });
  }
};
