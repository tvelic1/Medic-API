const jwt = require('jsonwebtoken');

// Import the JWT secret key from the constants file
const JWT_SECRET = "25591d6c2260457b4cdc04aad1bcd1a6838713b848d093d5103646021f0791a19a79934cfb5ced364e98781ef1d4a237dbe31d47745d3d467796e14020e1e41a"

function sign(payload, options = null) {
    if (!options) {
        return jwt.sign(payload, JWT_SECRET);
    }

    return jwt.sign(payload, JWT_SECRET, options);
}

/**
 * Verify a JWT token with the JWT secret key.
 *
 * @param {string} token - The JWT token to verify.
 * @returns {Object} The decoded payload if the token is valid.
 * @throws {Error} If the token is not valid.
 */
function verify(token) {
    return jwt.verify(token, JWT_SECRET);
}

module.exports = {
    sign,
    verify
};