const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./models/userModel');
require('dotenv').config();

const passwordToHash = 'admin123';
const username = 'admin';
const email = 'admin@site.com';
const mongoUri = process.env.MONGO_URI;

async function seedAdmin() {
  await mongoose.connect(mongoUri);
  const passwordHash = bcrypt.hashSync(passwordToHash, 10);

  // Eğer admin zaten varsa tekrar ekleme
  const existing = await User.findOne({ username });
  if (existing) {
    console.log('Admin zaten var.');
    process.exit(0);
  }

  await User.create({ username, email, passwordHash, role: 'superadmin' });
  console.log('Superadmin kullanıcı başarıyla eklendi!');
  const allUsers = await User.find();
  console.log('Tüm kullanıcılar:', allUsers);
  process.exit(0);
}

seedAdmin();