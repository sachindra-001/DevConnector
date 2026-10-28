const express = require('express')
const router = express.Router()
const { check, validationResult } = require('express-validator')
const User = require('../../models/User')
const gravatar = require('gravatar')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')

// Register user
router.post(
  '/',
  [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check(
      'password',
      'Please enter a password with 6 or more characters',
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() })
    }

    const { name, email, password } = req.body

    try {
      // Check whether the user already exists
      let user = await User.findOne({ email })

      if (user) {
        return res.status(400).json({
          errors: [{ msg: 'User already exists' }],
        })
      }

      // Generate Gravatar URL
      const avatar = gravatar.url(email, { s: '200', r: 'pg', d: 'mm' }, true)

      // Create user
      user = new User({
        name,
        email,
        avatar,
        password,
      })

      // Hash password
      const salt = await bcrypt.genSalt(10)
      user.password = await bcrypt.hash(password, salt)

      // Save user to database
      await user.save()

      // Create JWT payload
      const payload = {
        user: {
          id: user.id,
        },
      }

      // Sign JWT
      const jwtSecret = config.get('jwtSecret')

      jwt.sign(payload, jwtSecret, { expiresIn: '5 days' }, (err, token) => {
        if (err) {
          console.error('JWT signing error:', err)
          return res.status(500).json({ msg: 'Server error' })
        }

        return res.json({ token })
      })
    } catch (err) {
      console.error('Registration error:', err)
      return res.status(500).json({ msg: 'Server error' })
    }
  },
)

module.exports = router
