const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');

const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: [true, 'Full name is required'],
        trim: true,
        maxlength: [100, 'Full name cannot exceed 100 characters']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    institutionName: {
        type: String,
        required: [true, 'Institution name is required'],
        trim: true,
        maxlength: [200, 'Institution name cannot exceed 200 characters']
    },
    studentId: {
        type: String,
        required: [true, 'Student ID is required'],
        unique: true,
        trim: true,
        maxlength: [50, 'Student ID cannot exceed 50 characters']
    },
    department: {
        type: String,
        required: [true, 'Department is required'],
        trim: true,
        maxlength: [100, 'Department cannot exceed 100 characters']
    },
    course: {
        type: String,
        required: [true, 'Course is required'],
        trim: true,
        maxlength: [100, 'Course cannot exceed 100 characters']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [8, 'Password must be at least 8 characters long'],
        select: false
    },
    role: {
        type: String,
        enum: ['student', 'teacher', 'admin'],
        default: 'student'
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Middleware to update updatedAt before saving
userSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

// 10-layer encryption using bcrypt
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        // Layer 1: Initial hash
        let hashedPassword = await bcrypt.hash(this.password, 12);
        
        // Multiple layers of hashing (10 layers as requested)
        for (let i = 0; i < 9; i++) {
            hashedPassword = await bcrypt.hash(hashedPassword, 12);
        }
        
        this.password = hashedPassword;
        next();
    } catch (error) {
        next(error);
    }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        let currentHash = candidatePassword;
        
        // We need to apply the same 10 layers to the candidate password for comparison
        for (let i = 0; i < 10; i++) {
            currentHash = await bcrypt.hash(currentHash, 12);
        }
        
        return await bcrypt.compare(currentHash, this.password);
    } catch (error) {
        throw new Error('Password comparison failed');
    }
};

// Alternative method for direct comparison (more efficient)
userSchema.methods.comparePasswordDirect = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);