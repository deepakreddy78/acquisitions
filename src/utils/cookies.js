export const cookies = {
    getOption: () => ({
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000, // 15 minutes
    }),
    set: (res, name, value, options) => {
        res.cookie(name, value, { ...cookies.getOption(), ...options });
    },
    clear: (res, name, options = {}) => {
        res.clearCookie(name, { ...cookies.getOption(), ...options });
    },
    get: (req, name) => {
        return req.cookies[name];
    }
}


