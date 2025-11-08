const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { protect, authorize } = require('../middleware/auth');
const router = express.Router();

// Generate JWT Token
const sendTokenResponse = (user, statusCode, res) => {
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE
    });

    res.status(statusCode).json({
        success: true,
        token,
        user: {
            id: user._id,
            fullName: user.fullName,
            email: user.email,
            institutionName: user.institutionName,
            studentId: user.studentId,
            department: user.department,
            course: user.course,
            role: user.role
        }
    });
};

// @desc    Student Signup
// @route   POST /api/auth/student/signup
// @access  Public
router.post('/student/signup', async (req, res) => {
    try {
        const {
            fullName,
            email,
            institutionName,
            studentId,
            department,
            course,
            password,
            confirmPassword
        } = req.body;

        // Validation
        if (!fullName || !email || !institutionName || !studentId || !department || !course || !password || !confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Passwords do not match'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long'
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({
            $or: [
                { email: email.toLowerCase() },
                { studentId: studentId }
            ]
        });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User already exists with this email or student ID'
            });
        }

        // Create user
        const user = await User.create({
            fullName,
            email: email.toLowerCase(),
            institutionName,
            studentId,
            department,
            course,
            password,
            role: 'student'
        });

        sendTokenResponse(user, 201, res);

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({
            success: false,
            message: 'Error in creating account',
            error: error.message
        });
    }
});

// @desc    Student Login
// @route   POST /api/auth/student/login
// @access  Public
router.post('/student/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Please provide email and password'
            });
        }

        // Find user and include password field
        const user = await User.findOne({ email: email.toLowerCase() }).select('+password');

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Check if user is a student
        if (user.role !== 'student') {
            return res.status(403).json({
                success: false,
                message: 'Not authorized as student'
            });
        }

        // Check password
        const isMatch = await user.comparePasswordDirect(password);

        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        sendTokenResponse(user, 200, res);

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Error in login process',
            error: error.message
        });
    }
});

// @desc    Get current logged in student
// @route   GET /api/auth/student/me
// @access  Private
router.get('/student/me', protect, authorize('student'), async (req, res) => {
    try {
        const user = await User.findById(req.user.id);

        res.status(200).json({
            success: true,
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                institutionName: user.institutionName,
                studentId: user.studentId,
                department: user.department,
                course: user.course,
                role: user.role,
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// @desc    Update student profile
// @route   PUT /api/auth/student/profile
// @access  Private
router.put('/student/profile', protect, authorize('student'), async (req, res) => {
    try {
        const fieldsToUpdate = {
            fullName: req.body.fullName,
            institutionName: req.body.institutionName,
            department: req.body.department,
            course: req.body.course
        };

        const user = await User.findByIdAndUpdate(req.user.id, fieldsToUpdate, {
            new: true,
            runValidators: true
        });

        res.status(200).json({
            success: true,
            user: {
                id: user._id,
                fullName: user.fullName,
                email: user.email,
                institutionName: user.institutionName,
                studentId: user.studentId,
                department: user.department,
                course: user.course,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error updating profile'
        });
    }
});

module.exports = router;