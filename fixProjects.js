const mongoose = require('mongoose');
const Project = require('./models/projectModel');
require('dotenv').config();

async function fixProjects() {
  await mongoose.connect(process.env.MONGO_URI);

  const projects = await Project.find({});
  for (const project of projects) {
    let updated = false;
    if (!project.category) {
      project.category = 'Diğer';
      updated = true;
    }
    if (!project.createdBy) {
      project.createdBy = 'admin';
      updated = true;
    }
    if (!project.imageUrl) {
      // Yedek/resim yoksa dummy bir resim koyabilirsin
      project.imageUrl = '/uploads/1750868698707-s.jpg';
      updated = true;
    }
    if (updated) {
      await project.save();
      console.log(`Düzeltildi: ${project._id}`);
    }
  }
  console.log('Tüm projeler kontrol edildi ve eksikler tamamlandı.');
  process.exit(0);
}

fixProjects(); 