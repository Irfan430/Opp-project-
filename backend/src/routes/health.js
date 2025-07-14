const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const logger = require('../utils/logger');

/**
 * Basic health check endpoint
 */
router.get('/', async (req, res) => {
  try {
    const healthcheck = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '1.0.0',
      services: {
        database: 'unknown',
        redis: 'unknown',
        mlService: 'unknown'
      },
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024 * 100) / 100,
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024 * 100) / 100,
        external: Math.round(process.memoryUsage().external / 1024 / 1024 * 100) / 100
      }
    };

    // Check database connection
    try {
      const dbState = mongoose.connection.readyState;
      healthcheck.services.database = dbState === 1 ? 'connected' : 'disconnected';
    } catch (error) {
      healthcheck.services.database = 'error';
    }

    // Check Redis connection
    try {
      if (global.redis) {
        await global.redis.ping();
        healthcheck.services.redis = 'connected';
      } else {
        healthcheck.services.redis = 'not_configured';
      }
    } catch (error) {
      healthcheck.services.redis = 'error';
    }

    // Check ML service
    try {
      const axios = require('axios');
      const mlServiceUrl = process.env.ML_SERVICE_URL || 'http://localhost:8001';
      await axios.get(`${mlServiceUrl}/health`, { timeout: 5000 });
      healthcheck.services.mlService = 'connected';
    } catch (error) {
      healthcheck.services.mlService = 'error';
    }

    // Determine overall status
    const allServicesHealthy = Object.values(healthcheck.services).every(
      status => status === 'connected' || status === 'not_configured'
    );

    if (!allServicesHealthy) {
      healthcheck.status = 'DEGRADED';
      res.status(503);
    }

    res.json(healthcheck);
  } catch (error) {
    logger.error('Health check failed:', error);
    res.status(503).json({
      status: 'ERROR',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

/**
 * Detailed health check with dependencies
 */
router.get('/detailed', async (req, res) => {
  try {
    const detailed = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      node: {
        version: process.version,
        platform: process.platform,
        arch: process.arch
      },
      memory: {
        heapUsed: process.memoryUsage().heapUsed,
        heapTotal: process.memoryUsage().heapTotal,
        external: process.memoryUsage().external,
        rss: process.memoryUsage().rss
      },
      cpu: {
        usage: process.cpuUsage()
      },
      database: {
        status: 'unknown',
        connectionState: mongoose.connection.readyState,
        host: mongoose.connection.host,
        name: mongoose.connection.name
      },
      redis: {
        status: 'unknown'
      },
      mlService: {
        status: 'unknown',
        url: process.env.ML_SERVICE_URL || 'http://localhost:8001'
      }
    };

    // Test database
    try {
      const dbResult = await mongoose.connection.db.admin().ping();
      detailed.database.status = 'connected';
      detailed.database.ping = dbResult;
    } catch (error) {
      detailed.database.status = 'error';
      detailed.database.error = error.message;
    }

    // Test Redis
    try {
      if (global.redis) {
        const start = Date.now();
        await global.redis.ping();
        detailed.redis.status = 'connected';
        detailed.redis.responseTime = Date.now() - start;
      } else {
        detailed.redis.status = 'not_configured';
      }
    } catch (error) {
      detailed.redis.status = 'error';
      detailed.redis.error = error.message;
    }

    // Test ML service
    try {
      const axios = require('axios');
      const start = Date.now();
      const mlResponse = await axios.get(`${detailed.mlService.url}/health`, { timeout: 5000 });
      detailed.mlService.status = 'connected';
      detailed.mlService.responseTime = Date.now() - start;
      detailed.mlService.version = mlResponse.data.version;
    } catch (error) {
      detailed.mlService.status = 'error';
      detailed.mlService.error = error.message;
    }

    res.json(detailed);
  } catch (error) {
    logger.error('Detailed health check failed:', error);
    res.status(503).json({
      status: 'ERROR',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

/**
 * Readiness check for Kubernetes
 */
router.get('/ready', async (req, res) => {
  try {
    // Check if application is ready to serve traffic
    const isReady = mongoose.connection.readyState === 1;
    
    if (isReady) {
      res.status(200).json({
        status: 'ready',
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(503).json({
        status: 'not_ready',
        timestamp: new Date().toISOString(),
        reason: 'Database not connected'
      });
    }
  } catch (error) {
    logger.error('Readiness check failed:', error);
    res.status(503).json({
      status: 'not_ready',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

/**
 * Liveness check for Kubernetes
 */
router.get('/live', (req, res) => {
  // Simple liveness check - if we can respond, we're alive
  res.status(200).json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

/**
 * Database connectivity check
 */
router.get('/db', async (req, res) => {
  try {
    const start = Date.now();
    await mongoose.connection.db.admin().ping();
    const responseTime = Date.now() - start;

    res.json({
      status: 'connected',
      responseTime: `${responseTime}ms`,
      connectionState: mongoose.connection.readyState,
      host: mongoose.connection.host,
      name: mongoose.connection.name,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Database health check failed:', error);
    res.status(503).json({
      status: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Redis connectivity check
 */
router.get('/redis', async (req, res) => {
  try {
    if (!global.redis) {
      return res.status(503).json({
        status: 'not_configured',
        timestamp: new Date().toISOString()
      });
    }

    const start = Date.now();
    await global.redis.ping();
    const responseTime = Date.now() - start;

    res.json({
      status: 'connected',
      responseTime: `${responseTime}ms`,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Redis health check failed:', error);
    res.status(503).json({
      status: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

module.exports = router;