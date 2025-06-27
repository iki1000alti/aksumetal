const mongoose = require('mongoose');

const siteSettingsSchema = new mongoose.Schema({
  siteName: {
    type: String,
    required: true,
    default: 'DEMİR METAL',
  },
  homepage: {
    slider: [
      {
        imageUrl: { type: String, required: true },
        title: { type: String, default: '' },
        desc: { type: String, default: '' },
      }
    ],
    projects: {
      title: { type: String, default: '' },
      desc: { type: String, default: '' },
      button: { type: String, default: '' },
    },
    services: {
      title: { type: String, default: 'Hizmetlerimiz' },
      desc: { type: String, default: 'Metal sektöründe uçtan uca çözümler sunuyoruz.' },
      items: [
        {
          icon: { type: String, default: '' }, // ikon class veya isim
          title: { type: String, default: '' },
          desc: { type: String, default: '' },
        }
      ]
    },
  },
  about: {
    title: { type: String, default: 'Güven, Kalite, Yenilik' },
    description: { type: String, default: '20+ yıllık tecrübemizle metal sektöründe yenilikçi ve güvenilir çözümler sunuyoruz. Endüstriyel üretimden özel metal tasarımlara, montaj ve bakım hizmetlerinden proje danışmanlığına kadar geniş bir yelpazede hizmet veriyoruz. Uzman kadromuz ve modern tesislerimizle, her projede kaliteyi ve müşteri memnuniyetini ön planda tutuyoruz.' },
    values: [
      {
        icon: { type: String, default: '' },
        title: { type: String, default: '' },
        desc: { type: String, default: '' },
      }
    ],
    timeline: [
      {
        year: { type: String, default: '' },
        title: { type: String, default: '' },
        desc: { type: String, default: '' },
      }
    ],
    showValues: { type: Boolean, default: true },
    showTimeline: { type: Boolean, default: true },
    showTestimonials: { type: Boolean, default: true },
    testimonials: [
      {
        name: { type: String, default: '' },
        company: { type: String, default: '' },
        text: { type: String, default: '' },
      }
    ],
  },
  contact: {
    address: { type: String, default: '' },
    phone: { type: String, default: '' },
    email: { type: String, default: '' },
    mapsUrl: { type: String, default: '' },
  },
  footerText: {
    type: String,
    default: '',
  },
  logo: { type: String, default: '' },
  whatsapp: { type: String, default: '' },
  instagram: { type: String, default: '' },
  facebook: { type: String, default: '' },
}, {
  timestamps: true,
});

module.exports = mongoose.model('SiteSettings', siteSettingsSchema); 