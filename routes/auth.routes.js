const { Router } = require('express');
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = Router();

// /api/auth/register
router.post(
	'/register',
	[
		check('email', 'incorrect email').isEmail(),
		check('password', 'incorrect password').isLength({ min: 6 }),
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({
				errors: errors.array(),
				message: 'Incorrect registration data',
			});
		}
		try {
			const { email, password } = req.body;

			const candidate = await User.findOne({ email });
			if (candidate) {
				return res.status(400).json({ message: 'Such a user already exists' });
			}

			const hashPassword = await bcrypt.hash(password, 12);
			const user = new User({ email, password: hashPassword });

			await user.save();

			res.status(201).json({ message: 'User successfully created' });
		} catch (e) {
			res.status(500).json({ message: 'Error, please try again later.' });
		}
	}
);

// /api/auth/login
router.post(
	'/login',
	[
		check('email', 'Enter the correct email').normalizeEmail().isEmail(),
		check('password', 'Enter password').exists(),
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({
				errors: errors.array(),
				message: 'Incorrect data when logging in',
			});
		}
		try {
			const { email, password } = req.body;
			const user = await User.findOne({ email });
			if (!user) {
				return res
					.status(400)
					.json({ message: 'User not found or incorrect data' });
			}
			const isMatch = await bcrypt.compare(password, user.password);
			if (!isMatch) {
				return res
					.status(400)
					.json({ message: 'User not found or incorrect data' });
			}
			const token = jwt.sign({ userId: user.id }, config.get('jwtSecret'), {
				expiresIn: '1h',
			});
			res.json({ token, userId: user.id });
		} catch (e) {
			res.status(500).json({ message: 'Error, please try again later.' });
		}
	}
);

module.exports = router;
