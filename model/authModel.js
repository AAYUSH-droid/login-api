const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const validator = require('validator');
const uniqueValidator = require('mongoose-unique-validator');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is Required'],
    unique: true,
    validate: [validator.isEmail, 'Please Enter a valid Email'],
  },
  password: {
    type: String,
    required: [true, 'Password is Required'],
  },
  mobileNo: {
    type: String,
    required: [true, 'Mobile No is Required'],
    unique: true,
    validate: {
      validator: function (value) {
       
        return /^[789]\d{9}$/.test(value);
      },
    }
  },
  address: {
    type: String,
    required: [true, 'Address is Required'],
  },
  token:{
    type:String,
    default:'',
  },
});

userSchema.plugin(uniqueValidator);

userSchema.pre('save', async function (next) {
  const salt = await bcrypt.genSalt();
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.statics.login = async function (email, password) {
  const user = await this.findOne({ email });
  if (user) {
    const auth = await bcrypt.compare(password, user.password);
    if (auth) {
      return user;
    }
    throw Error('incorrect password');
  }
  throw Error('incorrect email');
};

module.exports = mongoose.model('Users', userSchema);
