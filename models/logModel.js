const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
  user: {
    type: String, // username
    required: true,
  },
  action: {
    type: String, // ör: login, logout, create_project, update_project, delete_project
    required: true,
  },
  target: {
    type: String, // ör: proje adı veya id'si
  },
  details: {
    type: String, // açıklama veya ek bilgi
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('Log', logSchema); 