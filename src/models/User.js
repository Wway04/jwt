module.exports = {
  createUser: async (connection, user) => {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    const query = "INSER INTO users(username, email, password) VALUES(?, ?, ?)";
    return await connection.execute(query, [user.username, user.email, hashedPassword]);
  },
  findUserByEmail: async (connection, email) => {
    const query = "SELECT * FROM users WHERE email = ?";
    const [rows] = await connection.execute(query, [email]);
    return rows[0];
  }
}