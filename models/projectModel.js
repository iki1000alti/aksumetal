const mongoose = require('mongoose');

const projectSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Lütfen bir başlık girin.'],
  },
  description: {
    type: String,
    required: [true, 'Lütfen bir açıklama girin.'],
  },
  imageUrl: {
    type: String,
    required: false,
  },
  imageUrls: {
    type: [String],
    required: false,
    default: []
  },
  defaultImage: {
    type: String,
    required: false,
  },
  createdBy: {
    type: String,
    required: true,
  },
  category: {
    type: String,
    required: [true, 'Lütfen bir kategori seçin.'],
  },
  likes: {
    type: Number,
    default: 0,
  },
}, {
  timestamps: true,
});

module.exports = mongoose.model('Project', projectSchema);