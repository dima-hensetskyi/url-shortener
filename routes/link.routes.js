const { Router } = require('express');
const Link = require('../models/Link');
const config = require('config');
const shortid = require('shortId');
const auth = require('../middleware/auth.middleware');
const router = Router();

router.post('/generate', auth, async (req, res) => {
	try {
		const baseUrl = config.get('baseUrl');
		const { from } = req.body;
		const code = shortid.generate();

		const existing = await Link.findOne({ from });
		if (existing) {
			return res.json({ link: existing });
		}
		const to = baseUrl + '/t/' + code;
		const newLink = new Link({
			code,
			to,
			from,
			owner: req.user.userId,
		});

		await newLink.save();
		res.status(201).json({ newLink });
	} catch (e) {
		res.status(500).json({ message: 'Error, please try again later.' });
	}
});
router.get('/', auth, async (req, res) => {
	try {
		const links = await Link.find({ owner: req.user.userId });
		res.json(links);
	} catch (e) {
		res.status(500).json({ message: 'Error, please try again later.' });
	}
});
router.get('/:id', auth, async (req, res) => {
	try {
		const link = await Link.findById(req.params.id);
		res.json(link);
	} catch (e) {
		res.status(500).json({ message: 'Error, please try again later.' });
	}
});

module.exports = router;
