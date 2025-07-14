const logger = require('../utils/logger');

/**
 * Setup Socket.IO event handlers
 * @param {Object} io - Socket.IO server instance
 */
function setupSocketHandlers(io) {
  io.on('connection', (socket) => {
    logger.info(`User connected: ${socket.user?.email || 'Anonymous'} (${socket.id})`);

    // Join user to their personal room
    if (socket.user) {
      socket.join(`user_${socket.user.id}`);
      socket.join(`org_${socket.user.organization || 'default'}`);
    }

    // Handle scan progress updates
    socket.on('subscribe_scan', (scanId) => {
      if (socket.user) {
        socket.join(`scan_${scanId}`);
        logger.debug(`User ${socket.user.email} subscribed to scan ${scanId}`);
      }
    });

    socket.on('unsubscribe_scan', (scanId) => {
      socket.leave(`scan_${scanId}`);
      logger.debug(`User ${socket.user?.email} unsubscribed from scan ${scanId}`);
    });

    // Handle real-time dashboard updates
    socket.on('subscribe_dashboard', () => {
      if (socket.user) {
        socket.join(`dashboard_${socket.user.id}`);
        logger.debug(`User ${socket.user.email} subscribed to dashboard updates`);
      }
    });

    // Handle phishing campaign tracking
    socket.on('subscribe_phishing', (campaignId) => {
      if (socket.user) {
        socket.join(`phishing_${campaignId}`);
        logger.debug(`User ${socket.user.email} subscribed to phishing campaign ${campaignId}`);
      }
    });

    // Handle disconnection
    socket.on('disconnect', () => {
      logger.info(`User disconnected: ${socket.user?.email || 'Anonymous'} (${socket.id})`);
    });

    // Handle errors
    socket.on('error', (error) => {
      logger.error('Socket error:', error);
    });
  });

  // Global socket utility functions
  io.sendToUser = (userId, event, data) => {
    io.to(`user_${userId}`).emit(event, data);
  };

  io.sendToOrganization = (organizationId, event, data) => {
    io.to(`org_${organizationId}`).emit(event, data);
  };

  io.sendScanUpdate = (scanId, data) => {
    io.to(`scan_${scanId}`).emit('scan_update', data);
  };

  io.sendDashboardUpdate = (userId, data) => {
    io.to(`dashboard_${userId}`).emit('dashboard_update', data);
  };

  io.sendPhishingUpdate = (campaignId, data) => {
    io.to(`phishing_${campaignId}`).emit('phishing_update', data);
  };

  logger.info('Socket.IO handlers initialized');
}

module.exports = setupSocketHandlers;