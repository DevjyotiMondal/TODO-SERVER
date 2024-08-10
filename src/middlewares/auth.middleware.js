import jwt from 'jsonwebtoken';
import ApiError from "../utilities/apiError.js";
import asyncHandlerFunction from "../utilities/asyncHandler.js";
import { User } from '../models/user.model.js';

const verifyJWT = asyncHandlerFunction(async (req, res, next) => {
    // Extract token from cookies or Authorization header
    const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "").trim();
      
    if (!token) {
        throw new ApiError(401, 'Token expired or not found');
    }

    // Verify the token
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    // Find the user by ID
    const user = await User.findById(decodedToken?._id);

    if (!user) {
        throw new ApiError(401, 'User not found');
    }

    // Assign the user to the request object
    req.user = user;

    next();
});

export { verifyJWT };
