const router = require('express').Router()
const bcrypt = require('bcryptjs')
const User = require('../users/users-model')
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
} = require('./auth-middleware')

// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post(
  '/register',
  checkPasswordLength,
  checkUsernameFree,
  async (req, res, next) => {
    const { username, password } = req.body
    const hash = bcrypt.hashSync(password, 10)
    const userForDB = { username, password: hash }
    try {
      const newUser = await User.add(userForDB)
      res.status(201).json(newUser)
    } catch (err) {
      next(err)
    }
  }
)

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.post('/login', checkUsernameExists, (req, res, next) => {
  console.log('test: ', req.session)
  try {
    if (bcrypt.compareSync(req.body.password, req.userExists.password)) {
      req.session.user = req.userExists
      res.json({ message: `Welcome ${req.userExists.username}!` })
    } else {
      res.status(401).json({ message: 'Invalid credentials' })
    }
  } catch (err) {
    next(err)
  }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

router.get('/logout', (req, res, next) => {
  try {
    if (req.session.user) {
      req.session.destroy((err) => {
        if (err) {
          next(err)
        } else {
          res.json({ message: 'logged out' })
        }
      })
    } else {
      res.json({ message: 'no session' })
    }
  } catch (err) {
    next(err)
  }
})

// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router
