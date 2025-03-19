# Hướng Dẫn Sử Dụng MySQL Với Node.js Và JWT Authentication

## Giới thiệu

Bài viết này trình bày cách sử dụng MySQL làm cơ sở dữ liệu cho ứng dụng Node.js, đặc biệt tập trung vào việc triển khai hệ thống xác thực người dùng sử dụng JWT (JSON Web Token). MySQL là một trong những hệ quản trị cơ sở dữ liệu phổ biến nhất, và kết hợp với JWT tạo nên giải pháp xác thực hiệu quả cho ứng dụng web hiện đại.

### Những gì bạn sẽ học trong hướng dẫn này:
- Thiết lập kết nối MySQL với Node.js
- Xây dựng hệ thống xác thực người dùng hoàn chỉnh
- Thực hiện bảo mật mật khẩu với bcrypt
- Triển khai JWT access và refresh token
- Tạo middleware để bảo vệ các route
- Tích hợp backend với frontend (Next.js)

## Thiết Lập MySQL Với Node.js

### Cài Đặt MySQL Driver

Bước đầu tiên để sử dụng MySQL với Node.js là cài đặt MySQL driver. Có hai lựa chọn phổ biến:

1. **mysql**: Driver truyền thống
```bash
npm install mysql
```

2. **mysql2**: Phiên bản cải tiến với hỗ trợ promise (khuyên dùng)
```bash
npm install mysql2
```

### Tạo Kết Nối Đến MySQL

#### Sử dụng mysql:
```javascript
const mysql = require('mysql');

// Tạo connection
const connection = mysql.createConnection({
  host: "localhost",
  user: "yourusername",
  password: "yourpassword",
  database: "yourdbname"
});

// Mở kết nối
connection.connect(function(err) {
  if (err) throw err;
  console.log("Connected to MySQL!");
});
```

#### Sử dụng mysql2 với Promises:
```javascript
const mysql = require('mysql2/promise');

// Tạo connection pool (tốt hơn cho production)
const pool = mysql.createPool({
  host: 'localhost',
  user: 'yourusername',
  password: 'yourpassword',
  database: 'yourdbname',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Sử dụng async/await
async function connectToDatabase() {
  try {
    const connection = await pool.getConnection();
    console.log("Connected to MySQL!");
    connection.release(); // Trả lại connection vào pool
  } catch (err) {
    console.error("Failed to connect to MySQL:", err);
  }
}

connectToDatabase();
```

### Tạo Cơ Sở Dữ Liệu và Bảng Users

```sql
-- Tạo database
CREATE DATABASE IF NOT EXISTS auth_demo;
USE auth_demo;

-- Tạo bảng users
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  refreshToken VARCHAR(255),
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Tạo index để tìm kiếm nhanh theo email
CREATE INDEX idx_email ON users(email);
```

## Xây Dựng Hệ Thống Xác Thực Với MySQL và JWT

### Cấu Trúc Thư Mục

Một dự án xác thực với MySQL và JWT nên có cấu trúc thư mục rõ ràng để dễ bảo trì:

```
├── src
│   ├── app.js              # Entry point
│   ├── config
│   │   ├── db.config.js    # Cấu hình database
│   │   └── env.config.js   # Biến môi trường
│   ├── controllers
│   │   └── auth.controller.js
│   ├── middlewares
│   │   └── authMiddleware.js
│   ├── models
│   │   └── user.model.js
│   ├── routes
│   │   └── auth.routes.js
│   └── utils
│       ├── password.utils.js
│       └── token.utils.js
├── .env                    # Biến môi trường (không commit lên git)
├── .gitignore
└── package.json
```

### Thiết Lập Cấu Hình

#### Cấu hình Database (db.config.js)

```javascript
// src/config/db.config.js
const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'auth_demo',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = pool;
```

#### Cấu hình Môi trường (.env)

```
# Database
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=auth_demo

# JWT
JWT_SECRET=your_secret_key_should_be_long_and_random
JWT_REFRESH_SECRET=another_secret_key_for_refresh_tokens
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Server
PORT=5000
NODE_ENV=development
FRONTEND_URL=http://localhost:3000
```

### Tạo Model User

```javascript
// src/models/user.model.js
const pool = require('../config/db.config');

module.exports = {
  createUser: async (user) => {
    const query = `INSERT INTO users (username, email, password) 
                  VALUES (?, ?, ?)`;
    const [result] = await pool.execute(query, [
      user.username, 
      user.email, 
      user.password
    ]);
    return result.insertId;
  },

  findUserByEmail: async (email) => {
    const query = `SELECT * FROM users WHERE email = ?`;
    const [rows] = await pool.execute(query, [email]);
    return rows[0];
  },

  findUserById: async (id) => {
    const query = `SELECT id, username, email, createdAt FROM users WHERE id = ?`;
    const [rows] = await pool.execute(query, [id]);
    return rows[0];
  },

  updateRefreshToken: async (userId, refreshToken) => {
    const query = `UPDATE users SET refreshToken = ? WHERE id = ?`;
    return await pool.execute(query, [refreshToken, userId]);
  },

  findUserByRefreshToken: async (refreshToken) => {
    const query = `SELECT * FROM users WHERE refreshToken = ?`;
    const [rows] = await pool.execute(query, [refreshToken]);
    return rows[0];
  }
};
```

### Utility Functions

#### Password Utils (password.utils.js)

```javascript
// src/utils/password.utils.js
const bcrypt = require('bcryptjs');

module.exports = {
  hashPassword: async (password) => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
  },

  comparePassword: async (password, hashedPassword) => {
    return await bcrypt.compare(password, hashedPassword);
  }
};
```

#### Token Utils (token.utils.js)

```javascript
// src/utils/token.utils.js
const jwt = require('jsonwebtoken');
require('dotenv').config();

module.exports = {
  generateTokens: (user) => {
    // Access token - thời gian ngắn
    const accessToken = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '15m' }
    );

    // Refresh token - thời gian dài hơn
    const refreshToken = jwt.sign(
      { id: user.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
    );

    return { accessToken, refreshToken };
  },

  verifyAccessToken: (token) => {
    try {
      return jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return null;
    }
  },

  verifyRefreshToken: (token) => {
    try {
      return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    } catch (error) {
      return null;
    }
  }
};
```

### Authentication Controller

```javascript
// src/controllers/auth.controller.js
const userModel = require('../models/user.model');
const { hashPassword, comparePassword } = require('../utils/password.utils');
const { generateTokens, verifyRefreshToken } = require('../utils/token.utils');

exports.register = async (req, res) => {
  try {
    // Validate request
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: "All fields are required" 
      });
    }

    // Check if user already exists
    const existingUser = await userModel.findUserByEmail(email);
    if (existingUser) {
      return res.status(409).json({ 
        success: false, 
        message: "Email already in use" 
      });
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Create user
    const userId = await userModel.createUser({ 
      username, 
      email, 
      password: hashedPassword 
    });

    res.status(201).json({ 
      success: true, 
      message: "User registered successfully",
      userId 
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error" 
    });
  }
};

exports.login = async (req, res) => {
  try {
    // Validate request
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: "Email and password are required" 
      });
    }

    // Find user
    const user = await userModel.findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: "Invalid credentials" 
      });
    }

    // Check password
    const isPasswordValid = await comparePassword(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ 
        success: false, 
        message: "Invalid credentials" 
      });
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    // Store refresh token in database
    await userModel.updateRefreshToken(user.id, refreshToken);

    // Send response
    res.json({
      success: true,
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error" 
    });
  }
};

exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ 
        success: false, 
        message: "Refresh token is required" 
      });
    }

    // Verify refresh token
    const decoded = verifyRefreshToken(refreshToken);
    if (!decoded) {
      return res.status(403).json({ 
        success: false, 
        message: "Invalid or expired refresh token" 
      });
    }

    // Find user by refresh token
    const user = await userModel.findUserByRefreshToken(refreshToken);
    if (!user) {
      return res.status(403).json({ 
        success: false, 
        message: "Invalid refresh token" 
      });
    }

    // Generate new tokens
    const tokens = generateTokens(user);

    // Update refresh token in database
    await userModel.updateRefreshToken(user.id, tokens.refreshToken);

    res.json({
      success: true,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken
    });
  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error" 
    });
  }
};

exports.logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ 
        success: false, 
        message: "Refresh token is required" 
      });
    }

    // Find user by refresh token
    const user = await userModel.findUserByRefreshToken(refreshToken);
    if (user) {
      // Remove refresh token from database
      await userModel.updateRefreshToken(user.id, null);
    }

    res.json({ 
      success: true, 
      message: "Logged out successfully" 
    });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error" 
    });
  }
};

exports.getProfile = async (req, res) => {
  try {
    // req.user được set bởi authMiddleware
    const user = await userModel.findUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error("Get profile error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Internal server error" 
    });
  }
};
```

### Auth Middleware

```javascript
// src/middlewares/authMiddleware.js
const { verifyAccessToken } = require('../utils/token.utils');

exports.verifyToken = (req, res, next) => {
  // Lấy token từ header Authorization
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      success: false, 
      message: "No token provided" 
    });
  }

  const token = authHeader.split(' ')[1];

  // Verify token
  const decoded = verifyAccessToken(token);
  if (!decoded) {
    return res.status(403).json({ 
      success: false, 
      message: "Invalid token or token expired" 
    });
  }

  // Set user info trong request object
  req.user = decoded;
  next();
};
```

### Routes

```javascript
// src/routes/auth.routes.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const { verifyToken } = require('../middlewares/authMiddleware');

// Auth routes
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh-token', authController.refreshToken);
router.post('/logout', authController.logout);

// Protected route
router.get('/profile', verifyToken, authController.getProfile);

module.exports = router;
```

### Main Application File

```javascript
// src/app.js
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const authRoutes = require('./routes/auth.routes');

const app = express();
const PORT = process.env.PORT || 5000;

// Middlewares
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/auth', authRoutes);

// Test route
app.get('/', (req, res) => {
  res.json({ message: "API is working!" });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: "Something went wrong!"
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

## Tích Hợp Với Next.js Frontend

### Cài Đặt Các Dependencies

```bash
# Trong thư mục frontend
npm install axios js-cookie
```

### Auth Service

```javascript
// services/auth.service.js
import axios from 'axios';
import Cookies from 'js-cookie';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000/api';

// Setup axios instance
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Interceptor để thêm token vào request
api.interceptors.request.use(
  (config) => {
    const token = Cookies.get('accessToken');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Interceptor để refresh token khi token hết hạn
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    // Nếu lỗi 403 (token hết hạn) và chưa thử refresh
    if (error.response?.status === 403 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        const refreshToken = Cookies.get('refreshToken');
        if (!refreshToken) {
          throw new Error('No refresh token');
        }
        
        // Gọi API để refresh token
        const response = await axios.post(`${API_URL}/auth/refresh-token`, {
          refreshToken
        });
        
        const { accessToken, refreshToken: newRefreshToken } = response.data;
        
        // Lưu token mới vào cookies
        Cookies.set('accessToken', accessToken, { expires: 1/96 }); // 15 phút
        Cookies.set('refreshToken', newRefreshToken, { expires: 7 }); // 7 ngày
        
        // Thử lại request cũ với token mới
        originalRequest.headers['Authorization'] = `Bearer ${accessToken}`;
        return axios(originalRequest);
      } catch (err) {
        // Nếu refresh token thất bại, đăng xuất
        logout();
        return Promise.reject(error);
      }
    }
    
    return Promise.reject(error);
  }
);

// Auth functions
export const register = async (username, email, password) => {
  try {
    const response = await api.post('/auth/register', {
      username,
      email,
      password
    });
    return {
      success: true,
      data: response.data
    };
  } catch (error) {
    return {
      success: false,
      message: error.response?.data?.message || 'Registration failed'
    };
  }
};

export const login = async (email, password) => {
  try {
    const response = await api.post('/auth/login', {
      email,
      password
    });
    
    const { accessToken, refreshToken, user } = response.data;
    
    // Lưu token và user info
    Cookies.set('accessToken', accessToken, { expires: 1/96 }); // 15 phút
    Cookies.set('refreshToken', refreshToken, { expires: 7 }); // 7 ngày
    localStorage.setItem('user', JSON.stringify(user));
    
    return {
      success: true,
      user
    };
  } catch (error) {
    return {
      success: false,
      message: error.response?.data?.message || 'Login failed'
    };
  }
};

export const logout = async () => {
  try {
    const refreshToken = Cookies.get('refreshToken');
    if (refreshToken) {
      await api.post('/auth/logout', { refreshToken });
    }
  } catch (error) {
    console.error('Logout error:', error);
  } finally {
    // Xóa token và user info
    Cookies.remove('accessToken');
    Cookies.remove('refreshToken');
    localStorage.removeItem('user');
  }
  
  return { success: true };
};

export const getProfile = async () => {
  try {
    const response = await api.get('/auth/profile');
    return {
      success: true,
      user: response.data.user
    };
  } catch (error) {
    return {
      success: false,
      message: error.response?.data?.message || 'Failed to fetch profile'
    };
  }
};

export default {
  register,
  login,
  logout,
  getProfile
};
```

### Auth Context

```jsx
// contexts/AuthContext.js
import React, { createContext, useState, useEffect, useContext } from 'react';
import { register, login, logout, getProfile } from '../services/auth.service';
import Cookies from 'js-cookie';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Kiểm tra xem người dùng đã đăng nhập chưa khi tải trang
  useEffect(() => {
    const loadUser = async () => {
      try {
        // Kiểm tra có token trong cookies không
        const token = Cookies.get('accessToken');
        if (!token) {
          setLoading(false);
          return;
        }

        // Lấy thông tin người dùng từ API
        const result = await getProfile();
        if (result.success) {
          setUser(result.user);
        }
      } catch (error) {
        console.error('Load user error:', error);
      } finally {
        setLoading(false);
      }
    };

    loadUser();
  }, []);

  // Auth functions
  const registerUser = async (username, email, password) => {
    setLoading(true);
    const result = await register(username, email, password);
    setLoading(false);
    return result;
  };

  const loginUser = async (email, password) => {
    setLoading(true);
    const result = await login(email, password);
    if (result.success) {
      setUser(result.user);
    }
    setLoading(false);
    return result;
  };

  const logoutUser = async () => {
    setLoading(true);
    await logout();
    setUser(null);
    setLoading(false);
    return { success: true };
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        isAuthenticated: !!user,
        register: registerUser,
        login: loginUser,
        logout: logoutUser
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
```

### Sử Dụng Auth Context trong _app.js

```jsx
// pages/_app.js
import '../styles/globals.css';
import { AuthProvider } from '../contexts/AuthContext';

function MyApp({ Component, pageProps }) {
  return (
    <AuthProvider>
      <Component {...pageProps} />
    </AuthProvider>
  );
}

export default MyApp;
```

### Protected Route Component

```jsx
// components/ProtectedRoute.js
import { useRouter } from 'next/router';
import { useAuth } from '../contexts/AuthContext';
import { useEffect } from 'react';

const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !isAuthenticated) {
      router.push('/login');
    }
  }, [isAuthenticated, loading, router]);

  if (loading) {
    return <div>Loading...</div>;
  }

  return isAuthenticated ? children : null;
};

export default ProtectedRoute;
```

### Sử Dụng Protected Route

```jsx
// pages/dashboard.js
import ProtectedRoute from '../components/ProtectedRoute';
import { useAuth } from '../contexts/AuthContext';

const Dashboard = () => {
  const { user, logout } = useAuth();

  return (
    <ProtectedRoute>
      <div>
        <h1>Dashboard</h1>
        {user && (
          <div>
            <p>Welcome, {user.username}!</p>
            <p>Email: {user.email}</p>
            <button onClick={logout}>Logout</button>
          </div>
        )}
      </div>
    </ProtectedRoute>
  );
};

export default Dashboard;
```

## Cải Tiến và Bảo Mật

### Best Practices

1. **Bảo mật mật khẩu**
   - Luôn sử dụng bcrypt để hash mật khẩu
   - Không lưu trữ mật khẩu dưới dạng văn bản thuần túy
   - Yêu cầu mật khẩu mạnh (trộn chữ hoa, chữ thường, số, ký tự đặc biệt)

2. **JWT Security**
   - Sử dụng khóa bí mật mạnh và khác nhau cho access token và refresh token
   - Thiết lập thời gian hết hạn ngắn cho access token (15-30 phút)
   - Lưu trữ refresh token trong database để có thể vô hiệu hóa

3. **Phòng chống tấn công**
   - Sử dụng Prepared Statements để ngăn SQL Injection
   - Thiết lập CORS đúng cách
   - Sử dụng rate limiting để ngăn brute force attacks

### Cải Tiến Hiệu Suất

1. **Connection Pool**
   - Sử dụng connection pool thay vì tạo kết nối mới mỗi lần
   - Cấu hình connectionLimit phù hợp với tài nguyên server

2. **Caching**
   - Sử dụng Redis để cache dữ liệu thường xuyên truy cập
   - Thiết lập caching cho các route không thay đổi thường xuyên

3. **Logging và Monitoring**
   - Sử dụng Winston hoặc Morgan để log requests
   - Theo dõi hiệu suất với APM tools như New Relic hoặc PM2

## Kết Luận

MySQL kết hợp với JWT là một giải pháp mạnh mẽ và linh hoạt cho việc xử lý xác thực người dùng trong ứng dụng web hiện đại. Bằng cách tuân thủ các nguyên tắc bảo mật như mã hóa mật khẩu, sử dụng access token và refresh token, bạn có thể xây dựng hệ thống xác thực an toàn và hiệu quả.

Khi triển khai hệ thống, đảm bảo lưu ý các vấn đề bảo mật như việc lưu trữ token an toàn, xử lý CORS đúng cách, và bảo vệ khỏi các cuộc tấn công phổ biến như SQL injection và XSS.

### Tài Liệu Tham Khảo
* [MySQL với Node.js - w3schools](https://www.w3schools.com/nodejs/nodejs_mysql.asp)
* [Node.js MySQL JWT Auth Example](https://github.com/desirekaleba/node-mysql-jwt-auth)
* [JWT Authentication với Node.js và MySQL](https://rahul6075.hashnode.dev/jwt-authentication-with-nodejs-and-mysql)
* [Secure User Authentication API with Express, JWT, bcrypt and MySQL](https://dev.to/gautam_kumar_d3daad738680/secure-user-authentication-api-with-express-jwt-bcrypt-and-mysql-16aj)
