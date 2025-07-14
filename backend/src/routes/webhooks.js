const express = require('express');
const router = express.Router();

router.post('/stripe', (req, res) => {
  res.status(501).json({ status: 'error', message: 'Stripe webhook endpoint not yet implemented' });
});

router.post('/paypal', (req, res) => {
  res.status(501).json({ status: 'error', message: 'PayPal webhook endpoint not yet implemented' });
});

module.exports = router;