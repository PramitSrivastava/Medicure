import User from "../models/UserSchema.js";
import Doctor from "../models/DoctorSchema.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET_key,
    {
      expiresIn: "30d",
    }
  );
};
export const register = async (req, res) => {
  const { email, password, name, role, photo, gender } = req.body;

  try {
    let user = null;

    if (role === "patient") {
      //check whether a user with given email is already present
      user = await User.findOne({ email });
    } else if (role === "doctor") {
      //check whether a doctor with given email is already present
      user = await Doctor.findOne({ email });
    }
    // when the user exist
    if (user) {
      return res.status(400).json({ message: "User already exist" });
    }
    // password hashing to store password securely in database
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);

    // creating a new user or doctor
    if (role === "patient") {
      user = new User({
        name,
        email,
        password: hashPassword,
        photo,
        gender,
        role,
      });
    }
    if (role === "doctor") {
      user = new Doctor({
        name,
        email,
        password: hashPassword,
        photo,
        gender,
        role,
      });
    }

    await user.save();
    res
      .status(200)
      .json({ success: true, message: "User Successfully Created" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    let user = null;

    const patient = await User.findOne({ email });
    const doctor = await Doctor.findOne({ email });

    // if we find patient/doctor with the given email we send them
    if (patient) {
      user = patient;
    }
    if (doctor) {
      user = doctor;
    }

    // check if user exists or not
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // compare password
    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      return res
        .status(400)
        .json({ status: false, message: "Invalid Credentials" });
    }

    // Generate token
    const token = generateToken(user);

    // Exclude sensitive information from the response
    const { password: _, role, appointments, ...userData } = user.toObject();

    res.status(200).json({
      status: true,
      message: "Successfully logged in",
      token,
      data: userData,
      role,
    });
  } catch (error) {
    res.status(500).json({ status: false, message: error.message });
  }
};
