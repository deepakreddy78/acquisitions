import logger from "#config/logger.js";
import bcrypt from "bcrypt";
import { eq } from "drizzle-orm";
import { db } from "#config/database.js";
import { user } from "#models/user.models.js";


export const hashPassword = async (password) => {
    try {
        return await bcrypt.hash(password, 10);
    }
    catch (e) {
        logger.error('Error hashing password:', { error: e });
        throw new Error('Could not hash password');
    }
}

export const createUser = async ({ name, email, password, role = "user" }) => {
    try {
        const existingUser = await db.select().from(user).where(eq(user.email, email)).limit(1);
        if (existingUser.length > 0) throw new Error('User already exists');

        const hash_password = await hashPassword(password);

        const [newUser] = await db.insert(user)
            .values({ name, email, password: hash_password, role })
            .returning({
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                created_at: user.created_at,
            });

        logger.info(`User created successfully, ${newUser.email}`);
        return newUser;

    } catch (e) {
        logger.error('Error creating user:', { error: e?.message || e });
        // ✅ Don't hide meaningful errors
        if (e.message === "User already exists") throw e;
        throw new Error(e.message || 'Could not create user');
    }
};