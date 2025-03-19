const mysql = require('mysql2');

// Thiết lập kết nối
const pool = mysql.createPool({
  host: 'localhost',
  port: 3306,
  charset: 'utf8mb4',  // Để chứa tiếng Việt
  user: 'root',
  password: '123123',
  database: 'matchmaking_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Kiểm tra kết nối
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Kết nối MySQL thất bại:', err);
  } else {
    console.log('Kết nối MySQL thành công!');
    connection.release(); // Giải phóng kết nối
  }
});

module.exports = pool;
