const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');
const mongoose = require('mongoose');
const fs = require('fs'); // Eski resimleri silmek için
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
require('dotenv').config();

const Project = require('./models/projectModel');
const { protect } = require('./middleware/authMiddleware');
const User = require('./models/userModel');
const Log = require('./models/logModel');
const SiteSettings = require('./models/siteSettingsModel');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 5001;

// Sadece http ile çalışan domainler için CORS izni veriyoruz (SSL yok)
const allowedOrigins = [
  'https://aksumetal.com',
  'https://www.aksumetal.com'
];

// CORS'u en üste al
app.use(cors({
  origin: allowedOrigins,
  credentials: true // Eğer cookie kullanıyorsanız
}));
app.options('*', cors());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB veritabanına başarıyla bağlanıldı.'))
  .catch((err) => console.error('Veritabanı bağlantı hatası:', err));

// Güvenlik middleware'leri
app.use(helmet());

// Rate limiting
const isDev = process.env.NODE_ENV !== 'production';
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: isDev ? 10000 : 100, // Geliştirmede çok yüksek, canlıda düşük
  message: 'Çok fazla istek gönderildi. Lütfen daha sonra tekrar deneyin.'
});
app.use('/api/', limiter);

// Login için daha sıkı rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: 5, // IP başına maksimum 5 login denemesi
  message: 'Çok fazla giriş denemesi. Lütfen 15 dakika sonra tekrar deneyin.'
});
app.use('/api/auth/login', loginLimiter);

app.use(express.json({ limit: '10mb' })); // JSON boyut limiti

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'aksumetal_uploads',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 1200, height: 800, crop: "limit" }],
  },
});

// Dosya filtreleme fonksiyonu
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Sadece resim dosyaları yüklenebilir!'), false);
  }
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  }
});

// Input sanitization fonksiyonu
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input
    .trim()
    .replace(/[<>]/g, '') // HTML tag'lerini kaldır
    .substring(0, 1000); // Maksimum 1000 karakter
};

// --- API ENDPOINTS ---

// GET: Tüm Projeler (kategoriye göre filtreleme destekli)
app.get('/api/projects', async (req, res) => {
  try {
    const { category } = req.query;
    let filter = {};
    if (category && category !== 'Tümü') {
      filter.category = category;
    }
    const projects = await Project.find(filter).sort({ createdAt: -1 });
    res.json(projects);
  } catch (error) {
    res.status(500).json({ message: 'Projeler getirilirken bir hata oluştu.' });
  }
});

// YENİ - GET: Tek Proje
app.get('/api/projects/:id', async (req, res) => {
    try {
        const project = await Project.findById(req.params.id);
        if (!project) {
            return res.status(404).json({ message: 'Proje bulunamadı' });
        }
        res.json(project);
    } catch (error) {
        res.status(500).json({ message: 'Proje getirilirken bir hata oluştu.' });
    }
});

// POST: Yeni Proje Ekle (ÇOKLU RESİM DESTEKLİ)
app.post('/api/projects', protect, upload.array('images', 10), async (req, res) => {
  const { title, description, category, defaultImage, defaultImageIndex } = req.body;
  if (!title || !description || !category || !req.files || req.files.length === 0) {
    return res.status(400).json({ message: 'Lütfen tüm alanları ve en az bir resim ekleyin.' });
  }
  try {
    const imageUrls = req.files.map(file => file.path); // Cloudinary URL'leri
    let defaultImg = imageUrls[0];
    if (typeof defaultImageIndex !== 'undefined' && !isNaN(Number(defaultImageIndex)) && imageUrls[Number(defaultImageIndex)]) {
      defaultImg = imageUrls[Number(defaultImageIndex)];
    } else if (defaultImage && imageUrls.includes(defaultImage)) {
      defaultImg = defaultImage;
    }
    const newProject = await Project.create({
      title: sanitizeInput(title),
      description: sanitizeInput(description),
      category: sanitizeInput(category),
      imageUrls,
      defaultImage: defaultImg,
      imageUrl: defaultImg, // Eski frontend desteği için
      createdBy: req.user.username,
    });
    await Log.create({ user: req.user.username, action: 'create_project', target: newProject._id.toString(), details: `Proje oluşturuldu: ${title}` });
    res.status(201).json(newProject);
  } catch (error) {
    res.status(500).json({ message: 'Proje eklenirken bir hata oluştu.' });
  }
});

// PUT: Proje Düzenle (ÇOKLU RESİM DESTEKLİ)
app.put('/api/projects/:id', protect, upload.array('images', 10), async (req, res) => {
  try {
    const { title, description, category, defaultImage } = req.body;
    let existingImages = req.body.existingImages;
    if (existingImages && !Array.isArray(existingImages)) {
      existingImages = [existingImages];
    }
    const project = await Project.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ message: 'Proje bulunamadı' });
    }
    // Silinen eski resimleri Cloudinary'den kaldır
    if (Array.isArray(existingImages)) {
      const toDelete = (project.imageUrls || []).filter(url => !existingImages.includes(url));
      for (const url of toDelete) {
        // Cloudinary public_id'yi URL'den çek
        const publicId = url.split('/').slice(-2).join('/').split('.')[0];
        try { await cloudinary.uploader.destroy(publicId); } catch (e) { /* ignore */ }
      }
    }
    // Yeni resimleri ekle
    let imageUrls = Array.isArray(existingImages) ? [...existingImages] : (project.imageUrls || []);
    if (req.files && req.files.length > 0) {
      const newImageUrls = req.files.map(file => file.path);
      imageUrls = imageUrls.concat(newImageUrls);
    }
    // Varsayılan fotoğrafı belirle
    let defaultImg = defaultImage && imageUrls.includes(defaultImage) ? defaultImage : imageUrls[0];
    const updatedData = {
      title: sanitizeInput(title) || project.title,
      description: sanitizeInput(description) || project.description,
      category: sanitizeInput(category) || project.category,
      imageUrls,
      defaultImage: defaultImg,
      imageUrl: defaultImg,
    };
    const updatedProject = await Project.findByIdAndUpdate(req.params.id, updatedData, { new: true });
    await Log.create({ user: req.user.username, action: 'update_project', target: req.params.id, details: `Proje güncellendi: ${updatedProject.title}` });
    res.json(updatedProject);
  } catch (error) {
    res.status(500).json({ message: 'Proje güncellenirken bir hata oluştu.' });
  }
});

// DELETE: Proje Sil
app.delete('/api/projects/:id', protect, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ message: 'Proje bulunamadı' });
    }
    // Eski resmi sunucudan sil (Artık gerek yok)
    // const imagePath = path.join(__dirname, project.imageUrl);
    // if (fs.existsSync(imagePath)) {
    //     fs.unlinkSync(imagePath);
    // }
    await Project.deleteOne({ _id: req.params.id });
    await Log.create({ user: req.user.username, action: 'delete_project', target: req.params.id, details: `Proje silindi: ${project.title}` });
    res.json({ message: 'Proje başarıyla silindi' });
  } catch (error) {
    res.status(500).json({ message: 'Proje silinirken bir sunucu hatası oluştu.' });
  }
});

// Tüm projeleri sil
app.delete('/api/projects', protect, async (req, res) => {
  try {
    const projects = await Project.find({});
    for (const project of projects) {
      for (const url of (project.imageUrls || [])) {
        const publicId = url.split('/').slice(-2).join('/').split('.')[0];
        try { await cloudinary.uploader.destroy(publicId); } catch (e) { /* ignore */ }
      }
    }
    await Project.deleteMany({});
    await Log.create({ user: req.user.username, action: 'delete_all_projects', details: 'Tüm projeler silindi' });
    res.json({ message: 'Tüm projeler ve resimleri silindi.' });
  } catch (error) {
    res.status(500).json({ message: 'Projeler silinirken bir hata oluştu.' });
  }
});

// Proje beğen (like) endpointi
app.post('/api/projects/:id/like', async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: 'Proje bulunamadı' });
    project.likes = (project.likes || 0) + 1;
    await project.save();
    res.json({ likes: project.likes });
  } catch (error) {
    res.status(500).json({ message: 'Beğeni artırılırken hata oluştu.' });
  }
});

// Proje beğenisini geri al (unlike) endpointi
app.post('/api/projects/:id/unlike', async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: 'Proje bulunamadı' });
    project.likes = Math.max((project.likes || 0) - 1, 0);
    await project.save();
    res.json({ likes: project.likes });
  } catch (error) {
    res.status(500).json({ message: 'Beğeni azaltılırken hata oluştu.' });
  }
});

// Tüm projelerin beğenisini sıfırla
app.post('/api/projects/clear-likes', async (req, res) => {
  try {
    await Project.updateMany({}, { $set: { likes: 0 } });
    res.json({ message: 'Tüm projelerin beğenileri sıfırlandı.' });
  } catch (error) {
    res.status(500).json({ message: 'Beğeniler sıfırlanırken hata oluştu.' });
  }
});

// POST: Admin Girişi
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya şifre' });
        }
        const isPasswordCorrect = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordCorrect) {
            return res.status(401).json({ message: 'Geçersiz kullanıcı adı veya şifre' });
        }
        user.lastLogin = new Date();
        await user.save();
        await Log.create({ user: user.username, action: 'login', details: 'Giriş yaptı' });
        const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Sunucuda bir hata oluştu' });
    }
});

// LOGOUT: (frontendde token silindiğinde de loglanabilir, burada endpoint ile de ekliyorum)
app.post('/api/auth/logout', protect, async (req, res) => {
    try {
        await Log.create({ user: req.user.username, action: 'logout', details: 'Çıkış yaptı' });
        res.json({ message: 'Çıkış loglandı' });
    } catch (error) {
        res.status(500).json({ message: 'Çıkış loglanamadı' });
    }
});

// --- ADMIN USER MANAGEMENT ENDPOINTS ---
// Tüm adminleri listele (sadece superadmin erişebilir)
app.get('/api/admin/users', protect, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
        const users = await User.find({}, '-passwordHash');
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Kullanıcılar getirilirken hata oluştu' });
    }
});
// Yeni admin ekle (sadece superadmin)
app.post('/api/admin/users', protect, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
        const { username, email, password, role } = req.body;
        if (!username || !password) return res.status(400).json({ message: 'Kullanıcı adı ve şifre zorunlu' });
        
        // Input sanitization
        const sanitizedUsername = sanitizeInput(username);
        const sanitizedEmail = email ? sanitizeInput(email) : undefined;
        
        const passwordHash = await bcrypt.hash(password, 10);
        const newUser = await User.create({ 
            username: sanitizedUsername, 
            email: sanitizedEmail, 
            passwordHash, 
            role: role || 'admin' 
        });
        res.status(201).json({ id: newUser._id, username: newUser.username, email: newUser.email, role: newUser.role });
    } catch (error) {
        res.status(500).json({ message: 'Kullanıcı eklenirken hata oluştu' });
    }
});
// Admin sil (sadece superadmin)
app.delete('/api/admin/users/:id', protect, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'Kullanıcı silindi' });
    } catch (error) {
        res.status(500).json({ message: 'Kullanıcı silinirken hata oluştu' });
    }
});
// Şifre değiştir (kendi şifresini değiştirebilir)
app.post('/api/admin/change-password', protect, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
        const isPasswordCorrect = await bcrypt.compare(oldPassword, user.passwordHash);
        if (!isPasswordCorrect) return res.status(401).json({ message: 'Mevcut şifre yanlış' });
        user.passwordHash = await bcrypt.hash(newPassword, 10);
        await user.save();
        res.json({ message: 'Şifre başarıyla değiştirildi' });
    } catch (error) {
        res.status(500).json({ message: 'Şifre değiştirilirken hata oluştu' });
    }
});
// Kendi profilini getir
app.get('/api/admin/profile', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
        res.json({ username: user.username, email: user.email, role: user.role, lastLogin: user.lastLogin });
    } catch (error) {
        res.status(500).json({ message: 'Profil getirilirken hata oluştu' });
    }
});

// Kullanıcı adı ile profil bilgisi (sadece superadmin)
app.get('/api/admin/user-profile', protect, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
        const { username } = req.query;
        if (!username) return res.status(400).json({ message: 'Kullanıcı adı zorunlu' });
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
        res.json({ username: user.username, role: user.role, lastLogin: user.lastLogin });
    } catch (error) {
        res.status(500).json({ message: 'Profil getirilirken hata oluştu' });
    }
});

// LOG LİSTELEME (sadece superadmin, pagination ve tarih filtresi destekler)
app.get('/api/admin/logs', protect, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
        const page = parseInt(req.query.page) || 1;
        const pageSize = parseInt(req.query.pageSize) || 10;
        const date = req.query.date;
        const filter = {};
        if (date) {
            // YYYY-MM-DD formatında bekleniyor
            const start = new Date(date);
            const end = new Date(date);
            end.setHours(23, 59, 59, 999);
            filter.createdAt = { $gte: start, $lte: end };
        }
        const total = await Log.countDocuments(filter);
        const logs = await Log.find(filter)
            .sort({ createdAt: -1 })
            .skip((page - 1) * pageSize)
            .limit(pageSize);
        res.json({ logs, total });
    } catch (error) {
        res.status(500).json({ message: 'Loglar getirilirken hata oluştu' });
    }
});

// Tüm adminlerin sayısını döndüren endpoint (herkes erişebilir)
app.get('/api/admin/usercount', protect, async (req, res) => {
    try {
        const count = await User.countDocuments();
        res.json({ count });
    } catch (error) {
        res.status(500).json({ message: 'Admin sayısı alınamadı' });
    }
});

// Superadmin: Admin şifresi sıfırla
app.post('/api/admin/users/:id/reset-password', protect, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
        const { newPassword } = req.body;
        if (!newPassword) return res.status(400).json({ message: 'Yeni şifre zorunlu' });
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
        user.passwordHash = await bcrypt.hash(newPassword, 10);
        await user.save();
        res.json({ message: 'Şifre başarıyla sıfırlandı' });
    } catch (error) {
        res.status(500).json({ message: 'Şifre sıfırlanırken hata oluştu' });
    }
});

// Tüm logları sil (sadece superadmin)
app.delete('/api/admin/logs', protect, async (req, res) => {
    try {
        if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
        await Log.deleteMany({});
        res.json({ message: 'Tüm loglar silindi' });
    } catch (error) {
        res.status(500).json({ message: 'Loglar silinirken hata oluştu' });
    }
});

// Admin güncelle (sadece superadmin)
app.put('/api/admin/users/:id', protect, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
    const { username, email, role } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
    if (username) user.username = username;
    if (email !== undefined) user.email = email;
    if (role) user.role = role;
    await user.save();
    res.json({ message: 'Kullanıcı başarıyla güncellendi' });
  } catch (error) {
    res.status(500).json({ message: 'Kullanıcı güncellenirken hata oluştu' });
  }
});

// --- SITE SETTINGS ENDPOINTS ---
// GET: Site ayarlarını getir
app.get('/api/site-settings', async (req, res) => {
  try {
    let settings = await SiteSettings.findOne();
    if (!settings) {
      // Varsayılan ayar yoksa oluştur
      settings = await SiteSettings.create({ siteName: 'AKSU METAL' });
    }
    res.json(settings);
  } catch (error) {
    res.status(500).json({ message: 'Site ayarları getirilirken hata oluştu.' });
  }
});
// PUT: Site ayarlarını güncelle (sadece superadmin)
app.put('/api/site-settings', protect, async (req, res) => {
  try {
    if (req.user.role !== 'superadmin') return res.status(403).json({ message: 'Yetki yok' });
    const { siteName, homepage, about, contact, footerText, logo, whatsapp, instagram, facebook } = req.body;
    let settings = await SiteSettings.findOne();
    if (!settings) {
      settings = await SiteSettings.create({ siteName, homepage, about, contact });
    } else {
      if (siteName !== undefined) settings.siteName = siteName;
      if (homepage !== undefined) {
        settings.homepage = {
          ...settings.homepage,
          ...homepage,
          projects: { ...settings.homepage.projects, ...homepage.projects },
          services: {
            ...settings.homepage.services,
            ...homepage.services,
            items: homepage.services?.items || settings.homepage.services?.items || [],
          },
          slider: homepage.slider || settings.homepage.slider,
        };
      }
      if (about !== undefined) {
        settings.about = {
          ...settings.about,
          ...about,
          values: (about.values && about.values.length > 0) ? about.values : settings.about.values,
          timeline: (about.timeline && about.timeline.length > 0) ? about.timeline : settings.about.timeline,
          testimonials: (about.testimonials && about.testimonials.length > 0) ? about.testimonials : settings.about.testimonials,
        };
      }
      if (contact !== undefined) settings.contact = { ...settings.contact, ...contact };
      if (footerText !== undefined) settings.footerText = footerText;
      if (logo !== undefined) settings.logo = logo;
      if (whatsapp !== undefined) settings.whatsapp = whatsapp;
      if (instagram !== undefined) settings.instagram = instagram;
      if (facebook !== undefined) settings.facebook = facebook;
      await settings.save();
    }
    res.json(settings);
  } catch (error) {
    res.status(500).json({ message: 'Site ayarları güncellenirken hata oluştu.' });
  }
});

// Slider görseli yükleme endpointi
app.post('/api/site-settings/slider-upload', protect, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'Dosya yüklenemedi' });
  res.json({ imageUrl: req.file.path }); // Cloudinary URL'si
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'Dosya boyutu çok büyük. Maksimum 5MB olmalı.' });
    }
    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({ message: 'Beklenmeyen dosya alanı.' });
    }
  }
  
  if (error.message === 'Sadece resim dosyaları yüklenebilir!') {
    return res.status(400).json({ message: error.message });
  }
  
  console.error('Sunucu hatası:', error);
  res.status(500).json({ message: 'Sunucuda bir hata oluştu' });
});

app.listen(PORT, () => {
  console.log(`Sunucu port ${PORT} üzerinde çalışıyor.`);
});
