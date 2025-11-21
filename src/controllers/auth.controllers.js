import logger from "#config/logger.js";
import { signUpSchema, signInSchema } from "#validations/auth.validation.js";
import { formValidationError } from "#utils/format.js";
import { createUser } from "#services/auth.services.js";
import { jwttoken } from "#utils/jwt.js";
import { cookies } from "#utils/cookies.js";
import { db } from "#config/database.js";
import { user } from "#models/user.models.js";
import { eq } from "drizzle-orm";
import bcrypt from "bcrypt";

export const signUp = async (req, res, next) => {
    try {
        const ValidationResult = signUpSchema.safeParse(req.body);
        if (!ValidationResult.success) {
            const errorMessage = formValidationError(ValidationResult.error);
            return res.status(400).json({ message: errorMessage });
        }
        const { name, email, password, role } = ValidationResult.data;
        const user = await createUser({ name, email, password, role });
        const token = jwttoken.sign({ id: user.id, email: user.email, role: user.role });
        cookies.set(res, 'token', token);

        logger.info(`SignUp request received, ${email}`);
        res.status(201).json({
            message: 'User registered successfully', user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    }
    catch (error) {
        logger.info('Error in signUp controller', { error });
        if (error.message === 'User already exists') {
            return res.status(409).json({ message: 'User already exists' });
        }
        next(error);
    }

}



export const signIn = async (req, res, next) => {
    try {
        const ValidationResult = signInSchema.safeParse(req.body);
        if (!ValidationResult.success) {
            const errorMessage = formValidationError(ValidationResult.error);
            return res.status(400).json({ message: errorMessage });
        }

        const { email, password } = ValidationResult.data;

        // 🔍 Find user by email
        const existingUser = await db.select().from(user).where(eq(user.email, email)).limit(1);
        if (existingUser.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const foundUser = existingUser[0];

        // 🔐 Compare password
        const isMatch = await bcrypt.compare(password, foundUser.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // 🔑 Generate JWT
        const token = jwttoken.sign({
            id: foundUser.id,
            email: foundUser.email,
            role: foundUser.role,
        });

        // 🍪 Set cookie
        cookies.set(res, "token", token);

        logger.info(`User signed in successfully: ${email}`);

        res.status(200).json({
            message: "Login successful",
            user: {
                id: foundUser.id,
                name: foundUser.name,
                email: foundUser.email,
                role: foundUser.role,
            },
        });
    } catch (error) {
        logger.error("Error in signIn controller", { error });
        next(error);
    }
};

export const signOut = async (req, res) => {
    try {
        cookies.clear(res, "token");
        logger.info("User signed out successfully");
        res.status(200).json({ message: "Logged out successfully" });
    } catch (error) {
        logger.error("Error during logout", { error });
        res.status(500).json({ message: "Error logging out" });
    }
};