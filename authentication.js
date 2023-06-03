const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;

const secretKey = 'secret';
app.use(express.json());
let users=[];
app.post('/register', (req, res) => {
  // Dapatkan data pengguna dari body request
  const { username, password } = req.body;
  
  // Hash password menggunakan bcrypt
  bcrypt.hash(password, 10, (err, hash) => {
    
  // Check apakah pengguna sudah ada
  const userExists = users.find(user => user.username === username);
  if (userExists) {
    return res.status(409).json({ message: 'Username sudah digunakan' });
  }
  // Simpan pengguna ke database atau penyimpanan lainnya
  users.push({ username, password });
    // Kirim respons sukses
    res.status(200).json({ message: 'Registrasi berhasil' });
  });
});

app.post('/login', (req, res) => {
    // Dapatkan data pengguna dari body request
    const { username, password } = req.body;
    
    // Verifikasi pengguna di database atau penyimpanan lainnya
    const user = users.find(user => user.username === username);

  if (!user) {
    return res.status(404).json({ message: 'Pengguna tidak ditemukan' });
  }
    
    // Contoh pengguna yang ditemukan
    
    
    // Periksa kecocokan password menggunakan bcrypt
    bcrypt.compare(password, user.password, (err, result) => {
      if (result) {
        // Buat JWT token
        const token = jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: '1h' });
        
        // Kirim token sebagai respons
        res.status(200).json({ token });
      } else {
        // Password tidak cocok
        res.status(401).json({ message: 'Login gagal' });
      }
    });
  });

  app.get('/protected', verifyToken, (req, res) => {
    // Endpoint hanya bisa diakses jika token valid
    res.status(200).json({ message: 'Endpoint terproteksi berhasil diakses' });
  });
  
  // Middleware untuk memverifikasi token
  function verifyToken(req, res, next) {
    // Dapatkan token dari header Authorization
    const token = req.headers.authorization;
    
    // Periksa apakah token ada
    if (!token) {
      return res.status(403).json({ message: 'Token tidak tersedia' });
    }
    
    // Verifikasi token
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Token tidak valid' });
      }
      
      // Token valid, simpan data pengguna yang terverifikasi ke request
      req.user = decoded;
      next();
    });
  }

  app.listen(port, () => {
    console.log(`Server berjalan di http://localhost:${port}`);
  });
  
  
