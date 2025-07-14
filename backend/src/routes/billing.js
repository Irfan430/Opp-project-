const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.status(501).json({ status: 'error', message: 'Get billing info endpoint not yet implemented' });
});

router.post('/subscribe', (req, res) => {
  res.status(501).json({ status: 'error', message: 'Subscribe endpoint not yet implemented' });
});

router.patch('/subscription', (req, res) => {
  res.status(501).json({ status: 'error', message: 'Update subscription endpoint not yet implemented' });
});

router.delete('/subscription', (req, res) => {
  res.status(501).json({ status: 'error', message: 'Cancel subscription endpoint not yet implemented' });
});

module.exports = router;