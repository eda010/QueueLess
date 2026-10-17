import mongoose from "mongoose";

// Strong password criteria rule pattern setup
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

// Pattern to detect if a password has already been hashed/scrambled by bcrypt
const bcryptRegex = /^\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}$/;

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    studentId: {
      type: String,
      required: false,
      sparse: true,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    password: {
      type: String,
      required: false,
      validate: {
        validator: function (v) {
          // 1. If password is not provided (like for Google Auth accounts), skip validation
          if (!v) return true;
          
          // 2. If the password is already hashed/scrambled by bcrypt, skip validation
          if (bcryptRegex.test(v)) return true;
          
          // 3. Test if a raw plain-text password matches our strong criteria parameters
          return passwordRegex.test(v);
        },
        message: "Password must be at least 8 characters long, contain an uppercase letter, a lowercase letter, a number, and a special character.",
      },
    },

    googleId: {
      type: String,
      sparse: true,
    },

    picture: {
      type: String,
    },

    role: {
      type: String,
      enum: ["student", "staff", "admin", "guest"],
      default: "student",
    },

    isPriority: {
      type: Boolean,
      default: false,
    },

    userType: {
      type: String,
      enum: ["priority", "normal"],
      default: "normal",
    },

    approvalStatus: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "approved",
    },

    phone: {
      type: String,
      trim: true,
      default: "",
    },

    lastLogin: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

const User = mongoose.model("User", userSchema);

export default User;
