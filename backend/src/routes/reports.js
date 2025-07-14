const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.status(501).json({ status: 'error', message: 'Get reports endpoint not yet implemented' });
});

router.post('/', (req, res) => {
  res.status(501).json({ status: 'error', message: 'Create report endpoint not yet implemented' });
});

router.get('/:id', (req, res) => {
  res.status(501).json({ status: 'error', message: 'Get report by ID endpoint not yet implemented' });
});

router.get('/:id/download', (req, res) => {
  res.status(501).json({ status: 'error', message: 'Download report endpoint not yet implemented' });
});

module.exports = router;