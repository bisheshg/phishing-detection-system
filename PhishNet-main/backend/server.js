import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import cors from "cors";

import authRoute from "./routes/auth.js";
import usersRoute from "./routes/users.js";
import phishingRoute from "./routes/phishing.js";
import reportDomainRoute from "./routes/reportDomain.js";

// Import security middleware
import {
  applySecurityMiddleware,
  analyzeRateLimiter,
  reportRateLimiter
} from "./middleware/security.js";

dotenv.config();
const app = express();

// Allowed origins
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5500",
];

// CORS middleware — also allow Chrome extension origins
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin) || origin.startsWith('chrome-extension://')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,        // ✅ allow cookies
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
}));

// Middlewares
app.use(express.json());
app.use(cookieParser());

// Apply comprehensive security middleware
applySecurityMiddleware(app);

// Routes with specific rate limiters
app.use("/api/auth", authRoute);
app.use("/api/users", usersRoute);
app.use("/api/phishing", analyzeRateLimiter, phishingRoute);
app.use("/api/reportdomain", reportRateLimiter, reportDomainRoute);

// 404 handler — catches favicon.ico, logo192.png, and any unknown route
app.use((_req, res) => {
  res.status(404).json({ success: false, message: "Route not found" });
});

// Global error handler
app.use((err, _req, res, _next) => {
  console.error(err);
  const status = err.status || 500;
  res.status(status).json({
    success: false,
    message: err.message || "Something went wrong",
    stack: err.stack,
  });
});

// MongoDB connection
const connect = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("MongoDB connected");
  } catch (err) {
    console.error(err);
  }
};

const PORT = process.env.PORT || 8800;
const server = app.listen(PORT, async () => {
  await connect();
  console.log(`Server running on port ${PORT}`);
});

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(`❌ Port ${PORT} still in use. Run: lsof -ti:${PORT} | xargs kill -9`);
  } else {
    console.error("Server error:", err);
  }
  process.exit(1);
});

// Graceful shutdown — lets nodemon restart cleanly
process.on("SIGTERM", () => server.close(() => process.exit(0)));
process.on("SIGINT",  () => server.close(() => process.exit(0)));



// import express from "express"
// import dotenv from "dotenv"
// import mongoose from "mongoose"
// import cookieParser from "cookie-parser";
// import cors from "cors";

// // import { rateLimiter } from './middleware/rateLimiter.js'; // Import the rate limiter middleware
// // import { createClient } from "redis";

// import authRoute from "./routes/auth.js"
// import usersRoute from "./routes/users.js"

// import contactRoute from "./routes/contact.js"
// import paymentRoutes from "./routes/payment.js";
// import domainPage from "./routes/domainPage.js";
// import reportDomain from "./routes/reportDomain.js";

// const app = express()
// dotenv.config()

// // // Redis client setup
// // export const redisClient = createClient();
// // redisClient.connect().catch(console.error);

// // redisClient.on('connect', () => {
// //   console.log('Connected to Redis');
// // });

// // redisClient.on('error', (err) => {
// //   console.error(`Redis error: ${err}`);
// // });

// // Allowed origins for CORS
// const allowedOrigins = [
//   "http://localhost:5500",
//   "http://localhost:3000",
//   "chrome-extension://eafifecgdjhbdnmpodidiiodfdhgofnh",
// ];

// // Configure CORS to allow requests from the specified origins
// const corsOptions = {
//    origin: function (origin, callback) {
//       if (!origin || allowedOrigins.includes(origin)) {
//          callback(null, true);
//       } else {
//          callback(new Error("Not allowed by CORS"));
//       }
//    },
//    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
//    credentials: true,
//    optionsSuccessStatus: 204,
// };

// app.use(cors(corsOptions));

// // Apply the rate limiter to all requests
// // app.use(rateLimiter);
 
// const connect = async () => {
//    try {
//       await mongoose.connect(process.env.MONGO_URL, {
//          useNewUrlParser: true,
//          useUnifiedTopology: true,
//       });
//       console.log("connected to mongodb")
//    } catch (error) {
//       throw error;
//    }
// };


// mongoose.connection.on("disconnected", () => {
//    console.log("mongodb disconnected")
// })

// mongoose.connection.on("connected", () => {
//    console.log("mongodb connected")
// })

// app.get('/', (req, res) => {
//    res.send("Hello")
// })


// //middlewares
// app.use(express.json());
// app.use(cookieParser());

// // routes
// app.use("/api/auth", authRoute);
// app.use("/api/users", usersRoute);
// app.use("/api/pay", paymentRoutes)
// app.use("/api/domainpage", domainPage)
// app.use("/api/reportdomain", reportDomain)


// app.use("/api/contact", contactRoute);

// app.use((err, req, res, next) => {
//    const errorStatus = err.status || 500;
//    const errorMessage = err.message || "Something went wrong"
//    return res.status(errorStatus).json({
//       success: false,
//       status: errorStatus,
//       message: errorMessage,
//       stack: err.stack
//    })
// })


// const port = process.env.PORT || 8800;
// const host = '0.0.0.0'

// app.listen(port, host, () => {
//    connect()
//    console.log("connected to backend")
// })

// import express from 'express';
// import mongoose from 'mongoose';
// import dotenv from 'dotenv';
// import cors from 'cors';
// import cookieParser from 'cookie-parser';

// // Load environment variables
// dotenv.config();

// // Initialize Express app
// const app = express();
// const PORT = process.env.PORT || 5000;

// // ============ CORS Configuration (MUST BE FIRST) ============
// const corsOptions = {
//   origin: function (origin, callback) {
//     const allowedOrigins = [
//       'http://localhost:3000',
//       'http://localhost:3001',
//       'http://127.0.0.1:3000'
//     ];
    
//     if (!origin || allowedOrigins.indexOf(origin) !== -1) {
//       callback(null, true);
//     } else {
//       callback(null, true); // Allow in development
//     }
//   },
//   credentials: true,
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
// };

// app.use(cors(corsOptions));
// app.options('*', cors(corsOptions));

// // Middleware
// app.use(express.json({ limit: '10mb' }));
// app.use(express.urlencoded({ extended: true, limit: '10mb' }));
// app.use(cookieParser());

// // Request logging
// app.use((req, res, next) => {
//   console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
//   next();
// });

// // Health check
// app.get('/health', (req, res) => {
//   res.json({
//     status: 'OK',
//     message: 'Server is running',
//     timestamp: new Date().toISOString(),
//     cors: 'enabled'
//   });
// });

// // Test CORS
// app.get('/api/test-cors', (req, res) => {
//   res.json({
//     message: 'CORS is working!',
//     origin: req.get('origin')
//   });
// });

// // ============ Import Routes Safely ============
// let authRoutes, userRoutes, contactRoutes, domainPageRoutes, reportDomainRoutes;

// try {
//   authRoutes = (await import('./routes/auth.js')).default;
//   console.log('✅ Auth routes loaded');
// } catch (err) {
//   console.warn('⚠️  Auth routes not found:', err.message);
// }

// try {
//   userRoutes = (await import('./routes/users.js')).default;
//   console.log('✅ User routes loaded');
// } catch (err) {
//   console.warn('⚠️  User routes not found:', err.message);
// }

// try {
//   contactRoutes = (await import('./routes/contact.js')).default;
//   console.log('✅ Contact routes loaded');
// } catch (err) {
//   console.warn('⚠️  Contact routes not found:', err.message);
// }

// try {
//   domainPageRoutes = (await import('./routes/domainPage.js')).default;
//   console.log('✅ Domain routes loaded');
// } catch (err) {
//   console.warn('⚠️  Domain routes not found:', err.message);
// }

// try {
//   reportDomainRoutes = (await import('./routes/reportDomain.js')).default;
//   console.log('✅ Report routes loaded');
// } catch (err) {
//   console.warn('⚠️  Report routes not found:', err.message);
// }

// // ============ Register Routes ============
// if (authRoutes) app.use('/api/auth', authRoutes);
// if (userRoutes) app.use('/api/users', userRoutes);
// if (contactRoutes) app.use('/api/contact', contactRoutes);
// if (domainPageRoutes) app.use('/api/domain', domainPageRoutes);
// if (reportDomainRoutes) app.use('/api/report', reportDomainRoutes);

// // Root route
// app.get('/', (req, res) => {
//   res.json({
//     message: 'PhishNet API Server',
//     version: '1.0.0',
//     status: 'running',
//     endpoints: {
//       health: '/health',
//       testCors: '/api/test-cors',
//       auth: authRoutes ? '/api/auth' : 'not loaded',
//       users: userRoutes ? '/api/users' : 'not loaded',
//       contact: contactRoutes ? '/api/contact' : 'not loaded',
//       domain: domainPageRoutes ? '/api/domain' : 'not loaded',
//       report: reportDomainRoutes ? '/api/report' : 'not loaded',
//     },
//   });
// });

// // 404 handler
// app.use((req, res) => {
//   res.status(404).json({
//     error: 'Route not found',
//     path: req.path,
//   });
// });

// // Error handler
// app.use((err, req, res, next) => {
//   console.error('Error:', err.message);
//   res.status(err.status || 500).json({
//     error: err.message || 'Internal Server Error',
//     code: err.code || 'INTERNAL_ERROR',
//   });
// });

// // ============ MongoDB Connection ============
// const connectDB = async () => {
//   try {
//     const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/phishnet';
//     await mongoose.connect(mongoURI);
//     console.log('✅ MongoDB connected:', mongoose.connection.name);
//   } catch (error) {
//     console.error('❌ MongoDB connection error:', error.message);
//     console.log('⚠️  Server will run without database connection');
//   }
// };

// // Graceful shutdown
// process.on('SIGTERM', async () => {
//   console.log('SIGTERM received, shutting down...');
//   await mongoose.connection.close();
//   process.exit(0);
// });

// process.on('SIGINT', async () => {
//   console.log('\nSIGINT received, shutting down...');
//   await mongoose.connection.close();
//   process.exit(0);
// });

// // ============ Start Server ============
// const startServer = async () => {
//   try {
//     await connectDB();
    
//     app.listen(PORT, () => {
//       console.log('\n' + '='.repeat(60));
//       console.log('🚀 PhishNet Backend Server');
//       console.log('='.repeat(60));
//       console.log(`📡 URL:         http://localhost:${PORT}`);
//       console.log(`✅ CORS:        Enabled`);
//       console.log(`🗄️  Database:    ${mongoose.connection.readyState === 1 ? 'Connected' : 'Not connected'}`);
//       console.log('='.repeat(60));
//       console.log('\nEndpoints:');
//       console.log('  GET  /health');
//       console.log('  GET  /api/test-cors');
//       if (authRoutes) console.log('  POST /api/auth/login');
//       if (authRoutes) console.log('  POST /api/auth/register');
//       if (authRoutes) console.log('  POST /api/auth/verify');
//       console.log('='.repeat(60) + '\n');
//     });
//   } catch (error) {
//     console.error('❌ Failed to start server:', error.message);
//     process.exit(1);
//   }
// };

// startServer().catch(err => {
//   console.error('❌ Fatal error starting server:');
//   console.error(err);
//   process.exit(1);
// });

// export default server;

// import dotenv from "dotenv";
// import express from "express";
// import mongoose from "mongoose";
// import cookieParser from "cookie-parser";
// import cors from "cors";
// import helmet from "helmet";

// // Routes
// import authRoute from "./routes/auth.js";
// import usersRoute from "./routes/users.js";
// import contactRoute from "./routes/contact.js";
// import paymentRoutes from "./routes/payment.js";
// import domainPage from "./routes/domainPage.js";
// import reportDomain from "./routes/reportDomain.js";

// // Middleware
// import { generalLimiter, authLimiter, reportLimiter } from "./middleware/rateLimiter.js";
// import { requestLogger } from "./utils/logger.js";
// import logger from "./utils/logger.js";

// dotenv.config();
// const app = express();

// // Trust proxy for accurate IP addresses
// app.set('trust proxy', 1);

// // Security middleware
// app.use(helmet({
//   crossOriginResourcePolicy: { policy: "cross-origin" }
// }));

// // Logging middleware (should be early in the middleware chain)
// app.use(requestLogger);

// // Body parsing middleware
// app.use(express.json({ limit: '10mb' }));
// app.use(express.urlencoded({ extended: true, limit: '10mb' }));
// app.use(cookieParser());

// // CORS configuration
// const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [
//   "http://localhost:3000",
//   "http://localhost:3001",
// ];

// const corsOptions = {
//   origin: function (origin, callback) {
//     if (!origin || allowedOrigins.includes(origin)) {
//       callback(null, true);
//     } else {
//       logger.warn('CORS blocked request', { origin });
//       callback(new Error("Not allowed by CORS"));
//     }
//   },
//   methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
//   credentials: true,
//   optionsSuccessStatus: 204,
// };

// app.use(cors(corsOptions));

// // Apply rate limiting globally
// app.use(generalLimiter);

// // Health check endpoint (before authentication)
// app.get("/health", (req, res) => {
//   res.status(200).json({
//     status: 'OK',
//     timestamp: new Date().toISOString(),
//     uptime: process.uptime(),
//     environment: process.env.NODE_ENV || 'development'
//   });
// });

// // MongoDB connection with improved error handling
// const connect = async () => {
//   try {
//     await mongoose.connect(process.env.MONGO_URL, {
//       useNewUrlParser: true,
//       useUnifiedTopology: true,
//     });
//     logger.info("Connected to MongoDB");
//   } catch (error) {
//     logger.error("MongoDB connection error", { 
//       error: error.message, 
//       stack: error.stack 
//     });
//     process.exit(1);
//   }
// };

// mongoose.connection.on("disconnected", () => {
//   logger.warn("MongoDB disconnected");
// });

// mongoose.connection.on("connected", () => {
//   logger.info("MongoDB connected");
// });

// // Test route
// app.get("/", (req, res) => {
//   res.send("PhishNet Backend API is running");
// });

// // Apply specific rate limiting to auth routes
// app.use("/api/auth", authLimiter, authRoute);
// app.use("/api/reportdomain", reportLimiter, reportDomain);

// // Other routes
// app.use("/api/users", usersRoute);
// app.use("/api/pay", paymentRoutes);
// app.use("/api/domainpage", domainPage);
// app.use("/api/contact", contactRoute);

// // 404 handler
// app.use("*", (req, res) => {
//   logger.warn("Route not found", { 
//     method: req.method, 
//     url: req.originalUrl, 
//     ip: req.ip 
//   });
//   res.status(404).json({
//     success: false,
//     error: "Route not found",
//     message: `The requested endpoint ${req.originalUrl} does not exist`
//   });
// });

// // Global error handler (must be last)
// app.use((err, req, res, next) => {
//   const errorStatus = err.status || 500;
//   const errorMessage = err.message || "Something went wrong";
  
//   // Log the error
//   logger.error('Unhandled error', {
//     error: errorMessage,
//     status: errorStatus,
//     stack: err.stack,
//     method: req.method,
//     url: req.originalUrl,
//     ip: req.ip,
//     userAgent: req.get('User-Agent')
//   });

//   // Don't expose error details in production
//   const response = {
//     success: false,
//     status: errorStatus,
//     message: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : errorMessage
//   };

//   if (process.env.NODE_ENV !== 'production' && err.stack) {
//     response.stack = err.stack;
//   }

//   return res.status(errorStatus).json(response);
// });

// // Graceful shutdown
// process.on('SIGTERM', () => {
//   logger.info('SIGTERM received, shutting down gracefully');
//   process.exit(0);
// });

// process.on('SIGINT', () => {
//   logger.info('SIGINT received, shutting down gracefully');
//   process.exit(0);
// });

// // Handle uncaught exceptions
// process.on('uncaughtException', (err) => {
//   logger.error('Uncaught Exception', {
//     error: err.message,
//     stack: err.stack
//   });
//   process.exit(1);
// });

// // Handle unhandled promise rejections
// process.on('unhandledRejection', (reason, promise) => {
//   logger.error('Unhandled Rejection', {
//     reason: reason,
//     promise: promise
//   });
//   process.exit(1);
// });

// const port = process.env.PORT || 8801;
// const host = "0.0.0.0";

// const server = app.listen(port, host, () => {
//   connect();
//   logger.info(`Server started on http://${host}:${port}`, {
//     environment: process.env.NODE_ENV || 'development',
//     nodeVersion: process.version
//   });
// });

// export default server;



