const jwt = require('jsonwebtoken');
require('dotenv').config();

const protect = (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      // Token'ı header'dan al ('Bearer TOKEN_DEGERI')
      token = req.headers.authorization.split(' ')[1];

      // Token'ı doğrula
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // --- DÜZELTME BURADA ---
      // 'decoded' objesinden gelen kullanıcı bilgilerini 'req.user'a ata.
      // JWT'yi oluştururken `{ id: user._id, username: user.username }` kullandığımız için,
      // decoded objesi de bu alanları içerecektir.
      req.user = {
        id: decoded.id,
        username: decoded.username,
        role: decoded.role,
      };
      // -----------------------
      
      next(); // Her şey yolundaysa, bir sonraki adıma geç
    } catch (error) {
      console.error('Token doğrulama hatası:', error);
      res.status(401).json({ message: 'Yetki yok, token geçersiz' });
    }
  }

  if (!token) {
    res.status(401).json({ message: 'Yetki yok, token bulunamadı' });
  }
};

module.exports = { protect };
