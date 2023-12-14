const { register, login } = require('../controllers/authControllers');
const { checkUser } = require('../middlewares/authMiddleware');
const {
  forget_password,
  reset_password,
} = require('../controllers/authControllers');

const router = require('express').Router();

router.post('/', checkUser);
router.post('/register', register);
router.post('/login', login);

router.post('/forget-password', forget_password);

router.post('/reset-password', reset_password);

module.exports = router;
