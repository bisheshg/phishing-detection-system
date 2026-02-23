export const createError=(status,message)=>{
    const err= new Error();
    err.status=status;
    err.message=message;
    return err;
}


// export class AppError extends Error {
//   constructor(message, statusCode, code) {
//     super(message);
//     this.statusCode = statusCode;
//     this.code = code;
//     this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
//     this.isOperational = true;

//     Error.captureStackTrace(this, this.constructor);
//   }
// }

// export const createError = (statusCode, message, code) => {
//   return new AppError(message, statusCode, code);
// };

// // Common error creators
// export const notFoundError = (resource = 'Resource') => {
//   return new AppError(`${resource} not found`, 404, 'NOT_FOUND');
// };

// export const validationError = (message = 'Validation failed') => {
//   return new AppError(message, 400, 'VALIDATION_ERROR');
// };

// export const authenticationError = (message = 'Authentication failed') => {
//   return new AppError(message, 401, 'AUTHENTICATION_ERROR');
// };

// export const authorizationError = (message = 'Not authorized') => {
//   return new AppError(message, 403, 'AUTHORIZATION_ERROR');
// };

// export const conflictError = (message = 'Resource already exists') => {
//   return new AppError(message, 409, 'CONFLICT_ERROR');
// };

// export const rateLimitError = (message = 'Too many requests') => {
//   return new AppError(message, 429, 'RATE_LIMIT_ERROR');
// };

// export const serverError = (message = 'Internal server error') => {
//   return new AppError(message, 500, 'INTERNAL_ERROR');
// };

// export default {
//   AppError,
//   createError,
//   notFoundError,
//   validationError,
//   authenticationError,
//   authorizationError,
//   conflictError,
//   rateLimitError,
//   serverError,
// };