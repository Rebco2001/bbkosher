// server.js

// Charger les modules nécessaires
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const Grid = require('gridfs-stream');
const crypto = require('crypto');
const path = require('path');
const { GridFSBucket } = require('mongodb');
const mime = require('mime-types');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');
const PDFDocument = require('pdfkit');
const nodemailer = require('nodemailer');

// Initialisation d'Express et configuration du port
const app = express();
const port = 3002;
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
      return res.status(401).json({ error: 'Non autorisé' });
  }

  const token = authHeader.split(' ')[1];
  try {
      const decoded = jwt.verify(token, 'Dadou6497');
      req.userId = decoded.userId;

      // Cherchez l'utilisateur et ajoutez `isAdmin` au req
      const user = await User.findById(req.userId);
      req.isAdmin = user && user.isAdmin;
      next();
  } catch (error) {
      return res.status(401).json({ error: 'Token invalide' });
  }
};


// Initialisation de Stripe
const stripe = Stripe('sk_test_51QFDZrDuUrxKhGZJDnJP1BZ9raqE633rQldbKftIY7Ncg4xRIi8xDhED0nsbO1s4Ujs5grt8NhexnSJloMWmTdfu00gspsBsmY');

// Configurer les middlewares
app.use(bodyParser.json());
app.use(cors({ origin: 'http://localhost:3000' }));

// URI et connexion à MongoDB
const mongoURI = 'mongodb://localhost:27017/airbnb_clone';
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
const conn = mongoose.connection;

// Gestion des erreurs et initialisation de GridFS
let gfs, gridfsBucket;
conn.on('error', console.error.bind(console, 'MongoDB connection error:'));
conn.once('open', () => {
  console.log('MongoDB connected successfully');
  gridfsBucket = new GridFSBucket(conn.db, { bucketName: 'uploads' });
  gfs = Grid(conn.db, mongoose.mongo);
  gfs.collection('uploads');
});

// Configuration de stockage Multer pour les images
const storage = multer.memoryStorage();
const upload = multer({
  storage: multer.memoryStorage(),
});

// Schémas Mongoose
const listingSchema = new mongoose.Schema({
    title: { type: String, required: function () {
      return this.status !== 'draft'; // Non requis si le statut est 'draft'
    }, },
    description: { type: String, required: function () {
      return this.status !== 'draft'; // Non requis si le statut est 'draft'
    }, },
    price: { type: Number, required: function () {
      return this.status !== 'draft'; // Non requis si le statut est 'draft'
    }, min: 0 },  // Prix doit être positif
    adresse: String,
    rue: String,
    ville: String,
    codePostal: String,
    pays: String,
    chambre: { type: Number, required: function () {
      return this.status !== 'draft'; // Non requis si le statut est 'draft'
    }, min: 1 }, // Doit avoir au moins 1 chambre
    lit: { type: Number,required: function () {
      return this.status !== 'draft'; // Non requis si le statut est 'draft'
    }, min: 1 },  // Doit avoir au moins 1 lit
    litEnfantd: { type: Number, min: 0, default: 0 }, // Peut avoir 0 lit enfant
    guests: { type: Number, min: 1, default: 1 }, // Doit avoir au moins 1 couchage
    couchages: [{
      type: { type: String, enum: ['chambre', 'salon'],required: function () {
        return this.status !== 'draft'; // Non requis si le statut est 'draft'
      }, },  // Type de la pièce (chambre ou salon)
      canapeLit: { type: Number, min: 0, default: 0 },  // Nombre de canapé-lits
      litSimple: { type: Number, min: 0, default: 0 },  // Nombre de lits simples
      litDouble: { type: Number, min: 0, default: 0 },  // Nombre de lits doubles
      litEnfant: { type: Number, min: 0, default: 0 }   // Nombre de lits enfants
    }],
    images: {
      type: [String], // Liste des noms de fichiers ou des URL
      validate: {
        validator: function (images) {
          // Valider si au moins une image est présente sauf pour les brouillons
          return this.status === 'draft' || (Array.isArray(images) && images.length > 0);
        },
        message: '{PATH} doit contenir au moins une image',
      },
    },
    amenities: [String],
    logement: String,
    logementType: String,
    hostFirstName: String,
    hostLastName: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    kosherValidation: Date,
    status: { type: String, default: 'pending', enum: ['pending', 'approved', 'rejected', 'draft'] },  // Statut par défaut à "pending"
    availability: [{
      date: { type: Date, required: true },
      price: { type: Number, required: true, default: 0 },  // Prix par jour
      available: { type: Boolean, default: false },
      notes: String
    }],
    hearts: [{type: mongoose.Schema.Types.ObjectId, ref: 'User', },

    ],
  }, { timestamps: true });
  
  const userSchema = new mongoose.Schema({
    isEmailVerified: { type: Boolean, default: false },
    verificationCode: { type: String },
    codeGeneratedAt: { type: Date },
    username: { type: String, required: false, unique: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, unique: true },
    password: { type: String, required: true },
    phone: { type: String, required: false }, // Nouveau champ pour le numéro de téléphone
    address: { type: String, required: false }, // Nouveau champ pour l'adresse
    isAdmin: { type: Boolean, default: false },
    respectShabbat: { type: String, enum: ['Oui', 'Non'], required: true },
    respectKosher: { type: String, enum: ['Oui', 'Non'], required: true },
    kosherHecher: { type: String },
    role: { type: String, enum: ['voyageur', 'hébergeur'], required: true, default: 'voyageur' },
    isHost: { type: Boolean, default: false },
  });
  
  const reservationSchema = new mongoose.Schema({
    listingId: { type: mongoose.Schema.Types.ObjectId, ref: 'Listing', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    status: { type: String, default: 'pending' },
    totalPrice: { type: Number, required: true },
    // Ajout des réponses du questionnaire
    travelerResponses: {
      respectShabbat: { type: String, enum: ['Oui', 'Non'] },
      respectKosher: { type: String, enum: ['Oui', 'Non'] },
      kosherHecher: { type: String }
    }
  }, { timestamps: true });
  
  
  const searchSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    criteria: mongoose.Schema.Types.Mixed, // Pour stocker les critères de recherche
  }, { timestamps: true });


// Modèles Mongoose
const Listing = mongoose.model('Listing', listingSchema);
const User = mongoose.model('User', userSchema);
const Reservation = mongoose.model('Reservation', reservationSchema);
const Search = mongoose.model('Search', searchSchema);

// Fonction utilitaire pour la validation des images
function arrayLimit(val) {
  return val.length > 0;
}

// Configuration de l'utilisateur administrateur
const createAdminUser = async () => {
  try {
    const existingAdmin = await User.findOne({ username: 'admin' });
    
    if (!existingAdmin) {
      // Créez un nouvel administrateur
      const admin = new User({
        username: 'admin', // Nom d'utilisateur de l'administrateur
        firstName: 'Admin',
        lastName: 'User',
        email: 'rebecca.illouz@gmail.com', // Optionnel
        password: bcrypt.hashSync('Dadou6497', 10), // Mot de passe sécurisé
        isAdmin: true
      });
      
      await admin.save();
      console.log('Compte administrateur créé avec succès.');
    } else {
      console.log('Un compte administrateur existe déjà.');
    }
  } catch (error) {
    console.error("Erreur lors de la création de l'administrateur:", error);
  }
};

// Routes d'authentification
app.post('/api/register', async (req, res) => {
  const { firstName, lastName, email, password, phone, address, respectShabbat, respectKosher, kosherHecher } = req.body;
  const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Utilisateur déjà existant' });
  
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
  
    const newUser = new User({
      firstName, lastName, email, password: hashedPassword, phone, address, respectShabbat, respectKosher, kosherHecher,
      verificationCode, codeGeneratedAt: new Date(),
    });
    await newUser.save();
  
    const mailOptions = {
      from: 'airbnbkosher26@gmail.com',
      to: email,
      subject: 'Code de vérification',
      text: `Votre code de vérification est ${verificationCode}. Il est valide pendant 10 minutes.`,
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) return res.status(500).json({ error: 'Erreur lors de l\'envoi de l\'email de vérification.' });
      res.status(201).json({ message: 'Inscription réussie. Vérifiez votre email pour activer votre compte.' });
    });
  });

  
  app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(400).json({ error: 'Utilisateur non trouvé.' });
    }
  
    if (!user.isEmailVerified) {
      return res.status(403).json({ error: 'Email non vérifié.', isEmailVerified: false });
    }
  
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Mot de passe incorrect.' });
    }
  
    const token = jwt.sign({ userId: user._id }, 'Dadou6497', { expiresIn: '1h' });
    res.json({ token, isEmailVerified: true });
  });
  
  
  app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
  
    if (!user || !user.isAdmin) {
      return res.status(401).json({ error: 'Identifiants administrateur invalides' });
    }
  
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Identifiants administrateur invalides' });
    }
  
    const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, 'Dadou6497', { expiresIn: '1h' });
    res.json({ token });
  });

// Routes pour les utilisateurs et les listings
app.get('/api/user', authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId, 'firstName lastName email isAdmin isHost');
  if (!user) return res.status(404).json({ error: 'Utilisateur non trouvé' });
  res.json(user);
});

app.get('/api/my-listings', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Non autorisé' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'Dadou6497');

    // Rechercher les annonces de l'utilisateur connecté
    const listings = await Listing.find({ userId: decoded.userId }).select('title ville price hearts images status');

    // Retourner les annonces avec le nombre de cœurs
    const listingsWithHeartsCount = listings.map((listing) => ({
      ...listing.toObject(),
      heartsCount: listing.hearts.length, // Calculer le nombre de cœurs
    }));

    res.json(listingsWithHeartsCount);
  } catch (error) {
    console.error('Erreur lors de la récupération des annonces :', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des annonces.' });
  }
});


app.get('/api/listings', async (req, res) => {
    try {
      // Filtrer pour ne récupérer que les annonces avec le statut 'approved'
      const listings = await Listing.find({ status: 'approved' });
      res.json(listings);
    } catch (error) {
      console.error('Erreur lors de la récupération des listings:', error);
      res.status(500).json({ error: 'Erreur lors de la récupération des listings' });
    }
  });

  app.get('/api/listings/:id/availability', async (req, res) => {
    try {
      const listing = await Listing.findById(req.params.id, 'availability');
      if (!listing) {
        return res.status(404).json({ error: 'Annonce non trouvée' });
      }
      res.json(listing.availability);
    } catch (error) {
      console.error('Erreur lors de la récupération de la disponibilité:', error);
      res.status(500).json({ error: 'Erreur lors de la récupération de la disponibilité' });
    }
  });
  
// Endpoint pour obtenir les détails d'une annonce spécifique
app.get('/api/listings/:id', async (req, res) => {
    try {
      const listing = await Listing.findById(req.params.id);
      if (!listing) {
        return res.status(404).json({ error: 'Annonce non trouvée' });
      }
      res.json(listing);
    } catch (error) {
      console.error('Erreur lors de la récupération de l\'offre:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  });

// Routes pour gérer les listings (création, mise à jour, suppression)
// Endpoint pour mettre à jour les détails de disponibilité et de prix pour une annonce
app.post('/api/listings/:id/details', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Non autorisé' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'Dadou6497');
    const listing = await Listing.findById(req.params.id);

    if (!listing) {
      return res.status(404).json({ error: 'Annonce non trouvée' });
    }

    if (listing.userId.toString() !== decoded.userId) {
      return res.status(403).json({ error: 'Non autorisé' });
    }

    const { dates, price, available, notes } = req.body;

    const today = new Date();
    today.setHours(0, 0, 0, 0); // Ignore l'heure pour la comparaison

    // Log des données reçues pour vérifier le contenu
    console.log('Données reçues:', { dates, price, available, notes });

    // Vérifier si toutes les dates sont valides
    const validDates = dates.every(({ date }) => {
      const parsedDate = new Date(date);
      return parsedDate instanceof Date && !isNaN(parsedDate); // Vérifie uniquement si la date est valide
    });
    

    if (!validDates) {
      return res.status(400).json({ error: 'Les dates passées ou réservées ne peuvent pas être modifiées' });
    }

    dates.forEach(({ date }) => {
      const parsedDate = new Date(date);
      const existingDate = listing.availability.find(d => d.date && d.date.toISOString() === parsedDate.toISOString());
      
      if (existingDate) {
        existingDate.price = price;
        existingDate.available = available;
        existingDate.notes = notes;
      } else {
        listing.availability.push({ date: parsedDate, price, available, notes });
      }
    });

    await listing.save();
    res.json(listing);
  } catch (error) {
    console.error('Erreur lors de la mise à jour des détails:', error);
    res.status(500).json({ error: 'Erreur lors de la mise à jour des détails' });
  }
});


//Endpoint pour supprimer une annonce
app.delete('/api/listings/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const listing = await Listing.findById(id);

    if (!listing) {
      return res.status(404).json({ error: 'Annonce non trouvée.' });
    }

    // Vérifiez si l'utilisateur est le propriétaire
    if (listing.userId.toString() !== req.userId) {
      return res.status(403).json({ error: 'Non autorisé : Vous n\'êtes pas le propriétaire de cette annonce.' });
    }

    // Utiliser `deleteOne` pour supprimer l'annonce
    await Listing.deleteOne({ _id: id });

    res.status(200).json({ message: 'Annonce supprimée avec succès.' });
  } catch (error) {
    console.error('Erreur lors de la suppression de l\'annonce :', error);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Endpoint pour créer une nouvelle annonce avec plusieurs images
app.post('/api/listings', (req, res, next) => {
  upload.array('images', 5)(req, res, (err) => {
      if (err instanceof multer.MulterError) {
          return res.status(400).json({ error: `Erreur Multer : ${err.message}` });
      } else if (err) {
          return res.status(500).json({ error: 'Erreur serveur lors du traitement des fichiers.' });
      }
      next();
  });
}, async (req, res) => {  // 'images' est le nom du champ
    try {
      const imageFilenames = [];
      
      // Stocker chaque image dans GridFS en utilisant Promise.all pour gérer les uploads simultanément
      if (req.files && req.files.length > 0) {
        const uploadPromises = req.files.map(file => {
          return new Promise((resolve, reject) => {
            const filename = crypto.randomBytes(16).toString('hex') + path.extname(file.originalname);
            const contentType = mime.lookup(file.originalname);
  
            const uploadStream = gridfsBucket.openUploadStream(filename, {
              contentType: contentType,
            });
  
            uploadStream.end(file.buffer, (err) => {
              if (err) {
                return reject(err);  // Si une erreur survient, on la renvoie
              }
              imageFilenames.push(filename);
              resolve();  // Résoudre la promesse quand l'upload est terminé
            });
          });
        });
  
        // Attendre que tous les fichiers soient uploadés
        await Promise.all(uploadPromises);
      }
  
      // Vérifier l'authentification de l'utilisateur
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
      const user = await User.findById(decoded.userId);
  
      if (!user) {
        return res.status(404).json({ error: 'Utilisateur non trouvé' });
      }

      // Log avant la création de l'annonce pour vérifier les données reçues
    console.log('Création de la nouvelle annonce avec les données suivantes:', {
      title: req.body.title,
      description: req.body.description,
      price: req.body.price,
      adresse: req.body.adresse,
      rue: req.body.rue,
      ville: req.body.ville,
      codePostal: req.body.codePostal,
      pays: req.body.pays,
      chambre: req.body.chambre,
      lit: req.body.lit,
      litEnfantd: req.body.litEnfantd,  // Vérifiez si ce champ est bien envoyé et existe
      guests: req.body.guests,
      couchages: req.body.couchages,
      amenities: req.body.amenities,
      logement: req.body.logement,
      logementType: req.body.logementType,
      images: imageFilenames,  // Vérifiez que les images sont bien collectées
    });

  
      // Créer une nouvelle annonce
      const newListing = new Listing({
        title: req.body.title,
        description: req.body.description,
        price: req.body.price,
        adresse: req.body.adresse,
        rue: req.body.rue,
        ville: req.body.ville,
        codePostal: req.body.codePostal,
        pays: req.body.pays,
        chambre: req.body.chambre,
        lit: req.body.lit,
        litEnfantd: req.body.litEnfantd,
        guests: req.body.guests,
        couchages: JSON.parse(req.body.couchages),
        amenities: JSON.parse(req.body.amenities),
        logement: req.body.logement,
        logementType: req.body.logementType,
        images: imageFilenames,  // Stocker les noms des fichiers d'images
        hostFirstName: user.firstName,
        hostLastName: user.lastName,
        userId: user._id,
        status: 'pending'
      });
      
      // Sauvegarder l'annonce
      await newListing.save();
  
      // Réponse avec l'annonce créée
      res.json(newListing);
    } catch (error) {
      console.error('Erreur lors de la création du listing:', error);
      res.status(500).json({ error: 'Erreur lors de la création du listing' });
    }
  });

  app.post('/api/listings/draft', authMiddleware, async (req, res) => {
    try {
      const { listingId } = req.body;
      let listing;
  
      // Si un `listingId` est fourni, mettre à jour le brouillon existant
      if (listingId) {
        listing = await Listing.findById(listingId);
        if (!listing || listing.status !== 'draft') {
          return res.status(404).json({ error: 'Brouillon non trouvé.' });
        }
      } else {
        // Sinon, créer un nouveau brouillon
        listing = new Listing({ userId: req.userId, status: 'draft' });
      }
  
      // Mettre à jour les champs (pas besoin de valider tous les champs)
      Object.assign(listing, req.body);
      await listing.save();
  
      res.status(201).json({ message: 'Brouillon enregistré.', listing });
    } catch (error) {
      console.error('Erreur lors de l\'enregistrement du brouillon:', error);
      res.status(500).json({ error: 'Erreur serveur.' });
    }
  });
  
  
// Endpoint pour mettre à jour une annonce
app.put('/api/listings/:id', upload.single('image'), authMiddleware, async (req, res) => {
  try {
    const listing = await Listing.findById(req.params.id);
    if (!listing) {
      return res.status(404).json({ error: 'Annonce non trouvée' });
    }

    // Vérifiez si l'utilisateur est le propriétaire
    if (listing.userId.toString() !== req.userId.toString()) {
      return res.status(403).json({ error: 'Non autorisé : vous n\'êtes pas le propriétaire de cette annonce.' });
    }

    const { title, description, price, couchages, amenities, ...otherData } = req.body;

    // Mettre à jour uniquement les champs nécessaires
    if (title !== undefined) listing.title = title;
    if (description !== undefined) listing.description = description;
    if (price !== undefined) listing.price = price;

    if (couchages !== undefined) {
      try {
        const parsedCouchages = JSON.parse(couchages); // Convertir en tableau si c'est un JSON
        if (Array.isArray(parsedCouchages)) {
          listing.couchages = parsedCouchages; // Mettre à jour les couchages avec le tableau
        } else {
          throw new Error('Format de couchages invalide');
        }
      } catch (error) {
        return res.status(400).json({ error: 'Format de couchages invalide.' });
      }
    }    
    

    // Gérer le champ `amenities` si présent
    if (amenities !== undefined) {
      try {
        const parsedAmenities = JSON.parse(amenities); // Convertir la chaîne JSON en tableau
        if (Array.isArray(parsedAmenities)) {
          listing.amenities = parsedAmenities.filter((amenity) => typeof amenity === 'string'); // Filtrer pour ne garder que des chaînes
        } else {
          throw new Error();
        }
      } catch (error) {
        return res.status(400).json({ error: 'Format des commodités invalide.' });
      }
    }

    // Mettre à jour d'autres champs (en excluant ceux qui ne doivent pas être modifiés)
    const excludedFields = ['hearts', 'availability'];
    Object.keys(otherData).forEach((key) => {
      if (!excludedFields.includes(key)) {
        listing[key] = otherData[key];
      }
    });

    await listing.save();
    res.json(listing);
  } catch (error) {
    console.error('Erreur lors de la mise à jour de l\'annonce :', error);
    res.status(500).json({ error: 'Erreur lors de la mise à jour de l\'annonce' });
  }
});

app.put('/api/listings/:id/images', authMiddleware, upload.array('newImages'), async (req, res) => {
  try {
    const listing = await Listing.findById(req.params.id);

    if (!listing) {
      return res.status(404).json({ error: 'Annonce non trouvée' });
    }

    // Vérifiez si l'utilisateur est le propriétaire
    if (listing.userId.toString() !== req.userId.toString()) {
      return res.status(403).json({ error: 'Non autorisé : vous n\'êtes pas le propriétaire de cette annonce.' });
    }

    // Récupérer l'ordre des images (si fourni)
    const imagesOrder = req.body.imagesOrder ? JSON.parse(req.body.imagesOrder) : [];

    // Vérifiez et appliquez l'ordre des images existantes
    if (Array.isArray(imagesOrder) && imagesOrder.length > 0) {
      listing.images = imagesOrder.filter((image) => listing.images.includes(image)); // Filtre pour conserver uniquement les images valides
    }

    // Ajouter les nouvelles images uploadées (si elles existent)
    if (req.files && req.files.length > 0) {
      const newImages = req.files.map((file) => file.filename); // Supposons que le nom des fichiers est sauvegardé
      listing.images = [...listing.images, ...newImages]; // Ajout des nouvelles images
    }

    // Sauvegarder les modifications
    await listing.save();
    res.status(200).json({ success: true, images: listing.images });
  } catch (error) {
    console.error('Erreur lors de la mise à jour des images :', error);
    res.status(500).json({ error: 'Erreur lors de la mise à jour des images.' });
  }
});
  
  
// Endpoint pour mettre à jour la disponibilité d'une annonce
app.post('/api/listings/:id/availability', async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
      const listing = await Listing.findById(req.params.id);
  
      if (listing.userId.toString() !== decoded.userId) {
        return res.status(403).json({ error: 'Non autorisé' });
      }
  
      listing.availability = req.body.availability;
      await listing.save();
      res.json(listing);
    } catch (error) {
      console.error('Erreur lors de la mise à jour de la disponibilité:', error);
      res.status(500).json({ error: 'Erreur lors de la mise à jour de la disponibilité' });
    }
  });
  
// Endpoint pour demander la validation kasher
app.post('/api/listings/:id/kosher-validation', async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
      const listing = await Listing.findById(req.params.id);
  
      if (listing.userId.toString() !== decoded.userId) {
        return res.status(403).json({ error: 'Non autorisé' });
      }
  
      listing.kosherValidation = req.body.kosherValidation;
      await listing.save();
      // Envoyer la demande à l'administrateur (à implémenter)
      res.json(listing);
    } catch (error) {
      console.error('Erreur lors de l\'envoi de la demande de validation:', error);
      res.status(500).json({ error: 'Erreur lors de l\'envoi de la demande de validation' });
    }
  });


// Routes pour l'administration des listings
app.get('/api/admin/listings/status/:status', authMiddleware, async (req, res) => {
    if (!req.isAdmin) return res.status(403).json({ error: 'Non autorisé' });
  
    const listings = await Listing.find({ status: req.params.status });
    res.json(listings);
});

// Endpoint pour approuver une annonce
app.post('/api/admin/listings/:id/approve', async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
  
      const user = await User.findById(decoded.userId);
      if (!user || !user.isAdmin) {
        return res.status(403).json({ error: 'Non autorisé' });
      }
  
      const listing = await Listing.findById(req.params.id);
      listing.status = 'approved';
      await listing.save();
      res.json(listing);
    } catch (error) {
      console.error('Erreur lors de l\'approbation de l\'offre:', error);
      res.status(500).json({ error: 'Erreur lors de l\'approbation de l\'offre' });
    }
  });
  
// Endpoint pour rejeter une annonce
app.post('/api/admin/listings/:id/reject', async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
  
      const user = await User.findById(decoded.userId);
      if (!user || !user.isAdmin) {
        return res.status(403).json({ error: 'Non autorisé' });
      }
  
      await Listing.findByIdAndDelete(req.params.id);
      res.json({ message: 'Offre rejetée avec succès' });
    } catch (error) {
      console.error('Erreur lors du rejet de l\'offre:', error);
      res.status(500).json({ error: 'Erreur lors du rejet de l\'offre' });
    }
  });
  
// Endpoint pour obtenir les annonces par statut
app.get('/api/admin/listings/status/:status', async (req, res) => {
    try {
      const { status } = req.params;
  
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
  
      const user = await User.findById(decoded.userId);
      if (!user || !user.isAdmin) {
        return res.status(403).json({ error: 'Non autorisé' });
      }
  
      const listings = await Listing.find({ status: status });
      res.json(listings);
    } catch (error) {
      console.error('Erreur lors de la récupération des listings par statut:', error);
      res.status(500).json({ error: 'Erreur lors de la récupération des listings par statut' });
    }
  });

// Endpoint pour mettre à jour le statut d'une annonce
app.put('/api/admin/listings/:id/status', async (req, res) => {
    try {
      const { status } = req.body;
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
  
      const user = await User.findById(decoded.userId);
      if (!user || !user.isAdmin) {
        return res.status(403).json({ error: 'Non autorisé' });
      }
  
      const listing = await Listing.findById(req.params.id);
      if (!listing) {
        return res.status(404).json({ error: 'Annonce non trouvée' });
      }
  
      listing.status = status;
      await listing.save();
      res.json(listing);
    } catch (error) {
      console.error("Erreur lors de la mise à jour du statut de l'offre:", error);
      res.status(500).json({ error: "Erreur lors de la mise à jour du statut de l'offre" });
    }
  });

  // Endpoint pour mettre à jour les détails d'une annonce
  app.get('/api/admin/listings/:id', authMiddleware, async (req, res) => {
    console.log("Utilisateur Admin :", req.isAdmin);
    console.log("ID demandé :", req.params.id);

    try {
        if (!req.isAdmin) {
            return res.status(403).json({ error: 'Accès non autorisé' });
        }

        const listing = await Listing.findById(req.params.id);
        if (!listing) {
            return res.status(404).json({ error: 'Annonce non trouvée' });
        }

        res.json(listing);
    } catch (error) {
        console.error('Erreur lors de la récupération de l\'annonce :', error);
        res.status(500).json({ error: 'Erreur lors de la récupération de l\'annonce' });
    }
});

//Endpoint pour suppimer une annonce en temps qu'admin
app.delete('/api/admin/listings/:id', authMiddleware, async (req, res) => {
  try {
    if (!req.isAdmin) {
      return res.status(403).json({ error: 'Accès non autorisé.' });
    }

    const { id } = req.params;

    const listing = await Listing.findById(id);
    if (!listing) {
      return res.status(404).json({ error: 'Annonce non trouvée.' });
    }

    // Utiliser `findByIdAndDelete` pour supprimer l'annonce directement
    await Listing.findByIdAndDelete(id);

    res.status(200).json({ message: 'Annonce supprimée avec succès.' });
  } catch (error) {
    console.error('Erreur lors de la suppression de l\'annonce :', error);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});


app.put('/api/admin/listings/:id', authMiddleware, upload.array('images', 10), async (req, res) => {
  try {
      if (!req.isAdmin) {
          return res.status(403).json({ error: 'Accès non autorisé' });
      }

      const listing = await Listing.findById(req.params.id);
      if (!listing) {
          return res.status(404).json({ error: 'Annonce non trouvée' });
      }

      // Mise à jour des champs
      const { title, description, price, amenities } = req.body;
      listing.title = title || listing.title;
      listing.description = description || listing.description;
      listing.price = price || listing.price;

      if (req.files) {
          const newImages = req.files.map((file) => file.filename);
          listing.images = [...listing.images, ...newImages];
      }

      if (amenities) {
          listing.amenities = JSON.parse(amenities);
      }

      await listing.save();
      res.json(listing);
  } catch (error) {
      console.error("Erreur lors de la mise à jour de l'annonce :", error);
      res.status(500).json({ error: "Erreur lors de la mise à jour de l'annonce" });
  }
});



  app.put('/api/admin/listings/:id/images', authMiddleware, async (req, res) => {
    try {
      if (!req.isAdmin) {
        return res.status(403).json({ error: 'Non autorisé' });
      }
  
      const { images } = req.body;
      if (!Array.isArray(images)) {
        return res.status(400).json({ error: 'Le champ images doit être un tableau.' });
      }
  
      const listing = await Listing.findById(req.params.id);
      if (!listing) {
        return res.status(404).json({ error: 'Annonce non trouvée' });
      }
  
      listing.images = images; // Mettre à jour les images
      await listing.save();
  
      res.json(listing);
    } catch (error) {
      console.error("Erreur lors de la mise à jour des images de l'annonce :", error);
      res.status(500).json({ error: "Erreur lors de la mise à jour des images de l'annonce" });
    }
  });
  
  

// Endpoint pour que l’administrateur puisse obtenir toutes les annonces
app.get('/api/admin/all-listings', authMiddleware, async (req, res) => {
  try {
    if (!req.isAdmin) {
      return res.status(403).json({ error: 'Accès non autorisé' });
    }

    const { page = 1, limit = 10 } = req.query; // Par défaut : page 1, 10 annonces par page
    const skip = (page - 1) * limit;

    const listings = await Listing.find().skip(skip).limit(Number(limit));
    const total = await Listing.countDocuments();

    res.json({ listings, total, pages: Math.ceil(total / limit) });
  } catch (error) {
    console.error('Erreur lors de la récupération des annonces pour l\'administrateur:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des annonces' });
  }
});



// Endpoint pour récupérer les annonces en fonction du statut pour l'administrateur
app.get('/api/admin/listings/status/:status', authMiddleware, async (req, res) => {
  try {
      const user = await User.findById(req.user.userId); // Récupération de l'utilisateur depuis le token

      if (!user || !user.isAdmin) {
          return res.status(403).json({ error: 'Accès non autorisé' });
      }

      // Récupère les annonces selon le statut spécifié
      const listings = await Listing.find({ status: req.params.status });
      res.json(listings);
  } catch (error) {
      console.error('Erreur lors de la récupération des annonces par statut:', error);
      res.status(500).json({ error: 'Erreur lors de la récupération des annonces' });
  }
});



// Routes pour la gestion des images
// Endpoint pour obtenir une image par nom de fichier
app.get('/image/:filename', async (req, res) => {
  try {
    const files = await gfs.files.find({ filename: req.params.filename }).toArray();
    if (!files || files.length === 0) {
      return res.status(404).json({ error: 'Aucun fichier trouvé' });
    }

    const file = files[0];
    if (file.contentType === 'image/jpeg' || file.contentType === 'image/png' || file.contentType === 'image/jpg') {
      const readstream = gridfsBucket.openDownloadStreamByName(file.filename);
      res.set('Content-Type', file.contentType);
      readstream.pipe(res);
    } else {
      res.status(404).json({ error: 'Pas une image' });
    }
  } catch (error) {
    console.error('Erreur lors de la récupération de l\'image:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération de l\'image' });
  }
});

// Routes pour les informations et mises à jour du profil utilisateur
// Endpoint pour récupérer les informations personnelles
app.get('/api/profile', async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
      const user = await User.findById(decoded.userId, 'firstName lastName email phone address respectShabbat respectKosher kosherHecher');
      if (!user) {
        return res.status(404).json({ error: 'Utilisateur non trouvé' });
      }
  
      res.json(user);
    } catch (error) {
      console.error('Erreur lors de la récupération des informations personnelles:', error);
      res.status(500).json({ error: 'Erreur lors de la récupération des informations personnelles' });
    }
  });
  
// Endpoint pour mettre à jour les informations personnelles
app.put('/api/profile', async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
      const { firstName, lastName, email, phone, address } = req.body;
  
      const user = await User.findByIdAndUpdate(decoded.userId, { firstName, lastName, email, phone, address }, { new: true });
      if (!user) {
        return res.status(404).json({ error: 'Utilisateur non trouvé' });
      }
  
      res.json(user);
    } catch (error) {
      console.error('Erreur lors de la mise à jour des informations personnelles:', error);
      res.status(500).json({ error: 'Erreur lors de la mise à jour des informations personnelles' });
    }
  });

  // Route pour mettre à jour le mot de passe
app.put('/api/profile/password', async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Non autorisé' });

  const token = authHeader.split(' ')[1];
  const decoded = jwt.verify(token, 'Dadou6497'); // Utilisez votre clé secrète
  const user = await User.findById(decoded.userId);

  // Vérifie si l'utilisateur existe
  if (!user) return res.status(404).json({ error: 'Utilisateur non trouvé' });

  // Vérifie si le mot de passe actuel est correct
  const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
  if (!isPasswordValid) return res.status(400).json({ error: 'Mot de passe actuel incorrect.' });

  // Hash le nouveau mot de passe et met à jour l'utilisateur
  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();

  res.json({ message: 'Mot de passe mis à jour avec succès.' });
});


// Routes pour les réservations
// Endpoint pour créer une réservation
app.post('/api/reservations', async (req, res) => {
  try {
    console.log('Données reçues dans le backend :', req.body);

    // Vérification de l'autorisation
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Non autorisé' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'Dadou6497');
    
    // Vérification de l'utilisateur et de ses réponses au questionnaire
    const traveler = await User.findById(decoded.userId, 'respectShabbat respectKosher kosherHecher');
    if (!traveler) {
      return res.status(404).json({ error: 'Voyageur non trouvé' });
    }

    if (!traveler.respectShabbat || !traveler.respectKosher || !traveler.kosherHecher) {
      return res.status(400).json({ 
        error: 'Veuillez remplir le questionnaire (Shabbat, Cacherout, Hécher) avant de faire une réservation.' 
      });
    }

    const { listingId, startDate, endDate } = req.body;

    // Validation des paramètres requis
    if (!listingId || !startDate || !endDate) {
      return res.status(400).json({ error: 'Paramètres manquants : listingId, startDate ou endDate.' });
    }    
    
    // Validation des dates
    const start = new Date(startDate);
    const end = new Date(endDate);

    if (isNaN(start) || isNaN(end) || start >= end) {
      return res.status(400).json({ error: 'Dates invalides ou mal formatées.' });
    }

    // Vérification de l'existence de l'annonce
    const listing = await Listing.findById(listingId);
    if (!listing) {
      return res.status(404).json({ error: 'Annonce non trouvée' });
    }

    // Calcul du prix total et vérification des disponibilités
    let totalPrice = 0;
    let currentDate = new Date(start);
    while (currentDate <= end) {
      const dayAvailability = listing.availability.find(avail =>
        avail.date.toISOString().split('T')[0] === currentDate.toISOString().split('T')[0] && avail.available
      );
      if (!dayAvailability) {
        return res.status(400).json({ error: `Date indisponible : ${currentDate.toISOString().split('T')[0]}` });
      }
      
      totalPrice += dayAvailability.price;
      dayAvailability.available = false;
      dayAvailability.notes = 'En attente de confirmation';
      currentDate.setDate(currentDate.getDate() + 1);
    }

    // Création de la réservation
    const newReservation = new Reservation({
      listingId,
      userId: decoded.userId,
      startDate: start,
      endDate: end,
      totalPrice,
      status: 'pending',
      travelerResponses: {
        respectShabbat: traveler.respectShabbat,
        respectKosher: traveler.respectKosher,
        kosherHecher: traveler.kosherHecher
      }
    });

    await newReservation.save();
    await listing.save();

    // Réponse de succès avec la réservation créée
    res.status(201).json(newReservation);
  } catch (error) {
    console.error('Erreur lors de la création de la réservation:', error);
    res.status(500).json({ error: 'Erreur lors de la création de la réservation' });
  }
});




  
// Endpoint pour que l'hôte accepte ou refuse une réservation
app.put('/api/reservations/:id/status', async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
      
      const reservation = await Reservation.findById(req.params.id).populate('listingId');
      if (!reservation) {
        return res.status(404).json({ error: 'Réservation non trouvée' });
      }
  
      if (reservation.listingId.userId.toString() !== decoded.userId) {
        return res.status(403).json({ error: 'Non autorisé' });
      }
  
      const { status } = req.body;
      reservation.status = status;
  
      let currentDate = new Date(reservation.startDate);
      while (currentDate <= new Date(reservation.endDate)) {
        const dateString = currentDate.toISOString().split('T')[0];
        const availability = reservation.listingId.availability.find(avail => 
          avail.date.toISOString().split('T')[0] === dateString);
        
        if (status === 'accepted') {
          if (availability) {
            availability.available = false;
            availability.notes = 'Réservation confirmée';
          }
        } else if (status === 'rejected') {
          if (availability) {
            availability.available = true; // Les dates redeviennent disponibles si la réservation est rejetée
            availability.notes = '';
          }
        }
        currentDate.setDate(currentDate.getDate() + 1);
      }
  
      await reservation.listingId.save();
      await reservation.save();
  
      res.json(reservation);
    } catch (error) {
      console.error('Erreur lors de la mise à jour du statut de la réservation:', error);
      res.status(500).json({ error: 'Erreur lors de la mise à jour du statut de la réservation' });
    }
  });

// Endpoint pour récupérer les réservations d'un utilisateur
app.get('/api/my-reservations', async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
      
      const reservations = await Reservation.find({ userId: decoded.userId }).populate('listingId');
      res.json(reservations);
    } catch (error) {
      console.error('Erreur lors de la récupération des réservations:', error);
      res.status(500).json({ error: 'Erreur lors de la récupération des réservations' });
    }
  });
  
// Endpoint pour récupérer les réservations d'un hôte
app.get('/api/host-reservations', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Non autorisé' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'Dadou6497');

    const listings = await Listing.find({ userId: decoded.userId });
    const listingIds = listings.map(listing => listing._id);

    const reservations = await Reservation.find({ listingId: { $in: listingIds } })
      .populate('listingId', 'title')
      .select('startDate endDate totalPrice status travelerResponses');

    const pendingCount = reservations.filter(reservation => reservation.status === 'pending').length;

    res.json({ reservations, pendingCount });
  } catch (error) {
    console.error('Erreur lors de la récupération des réservations:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des réservations' });
  }
});


// Endpoint pour obtenir le nombre de réservations en attente d'un utilisateur
app.get('/api/reservations/pending-count', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Non autorisé' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'Dadou6497');

    const listings = await Listing.find({ userId: decoded.userId });
    const listingIds = listings.map(listing => listing._id);

    // Compter les réservations avec le statut 'pending'
    const pendingCount = await Reservation.countDocuments({
      listingId: { $in: listingIds },
      status: 'pending',
    });

    res.json({ pendingCount });
  } catch (error) {
    console.error('Erreur lors de la récupération des réservations en attente:', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des réservations en attente' });
  }
});

// Endpoint pour Obtenir les Brouillons
app.get('/api/listings/drafts', authMiddleware, async (req, res) => {
  try {
    const drafts = await Listing.find({ userId: req.userId, status: 'draft' });
    res.json(drafts);
  } catch (error) {
    console.error('Erreur lors de la récupération des brouillons:', error);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});


// Routes pour la recherche de listings et sauvegarde des critères
// Endpoint pour rechercher les annonces avec filtres
app.post('/api/listings/search', async (req, res) => {
  try {
    console.log('Requête de recherche reçue :', req.body);
    const {
      destination,
      arrivalDate,
      departureDate,
      guests, // guests sera un objet contenant adultes et enfants
      logement,
      logementType,
      minPrice,
      maxPrice,
      chambres,
      lits,
      litsEnfant,
      amenities,
    } = req.body;

    // Construire le filtre MongoDB
    const filters = {
      status: 'approved', // N'afficher que les annonces approuvées
    };

    // Filtrage par destination
    if (destination) {
      filters.$or = [
        { ville: { $regex: destination, $options: 'i' } },
        { codePostal: { $regex: destination, $options: 'i' } },
      ];
    }

    // Filtrage par prix
    if (minPrice || maxPrice) {
      filters.price = {};
      if (minPrice) filters.price.$gte = minPrice;
      if (maxPrice) filters.price.$lte = maxPrice;
    }

    // Filtrage par nombre d'invités
    if (guests) {
      const totalGuests = (guests.adults || 0) + (guests.children || 0);
      filters.guests = { $gte: totalGuests };
    }

    // Filtrage par logement et logementType
    if (logement && logement !== 'all') filters.logement = logement;
    if (logementType && logementType !== 'all') filters.logementType = logementType;

    // Filtrage par chambres et lits
    if (chambres && chambres !== 'all') filters.chambre = parseInt(chambres);
    if (lits && lits !== 'all') filters.lit = parseInt(lits);

    // Filtrage par équipements
    if (amenities && amenities.length > 0) filters.amenities = { $all: amenities };

    // Filtrage par dates de disponibilité
    if (arrivalDate && departureDate) {
      const arrival = new Date(arrivalDate);
      const departure = new Date(departureDate);

      filters.availability = {
        $elemMatch: {
          date: { $gte: arrival, $lte: departure },
          available: true,
        },
      };
    }

    // Recherche des listings avec les filtres
    const listings = await Listing.find(filters);
    res.json(listings);
  } catch (error) {
    console.error('Erreur de recherche :', error);
    res.status(500).json({ error: 'Erreur lors de la recherche des listings' });
  }
});

// Endpoint pour sauvegarder une recherche
app.post('/api/search/save', async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
  
      const newSearch = new Search({
        userId: decoded.userId,
        criteria: req.body.criteria,
      });
      await newSearch.save();
      res.json(newSearch);
    } catch (error) {
      console.error('Erreur lors de la sauvegarde de la recherche:', error);
      res.status(500).json({ error: 'Erreur lors de la sauvegarde de la recherche' });
    }
  });
  
// Endpoint pour récupérer les recherches sauvegardées d'un utilisateur
app.get('/api/search/saved', async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ error: 'Non autorisé' });
      }
  
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, 'Dadou6497');
  
      const searches = await Search.find({ userId: decoded.userId });
      res.json(searches);
    } catch (error) {
      console.error('Erreur lors de la récupération des recherches:', error);
      res.status(500).json({ error: 'Erreur lors de la récupération des recherches' });
    }
  });

// Route pour la création d'une intention de paiement Stripe
app.post('/api/create-payment-intent', async (req, res) => {
  const { totalPrice } = req.body;
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: totalPrice * 100,
      currency: 'eur',
    });
    res.send({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Route pour récupérer les gains de l'hôte
app.get('/api/host-earnings', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Non autorisé' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'Dadou6497');
    
    // Obtenir tous les IDs des annonces de l'utilisateur
    const listings = await Listing.find({ userId: decoded.userId });
    const listingIds = listings.map(listing => listing._id);

    // Récupérer les réservations pour ces annonces et peupler les informations du logement
    const reservations = await Reservation.find({
      listingId: { $in: listingIds }
    }).populate('listingId'); // Peupler listingId pour obtenir le titre du logement

    // Variables pour les calculs de gains
    let totalEarnings = 0;
    const monthlyEarnings = {};
    const yearlyEarnings = {};
    const reservationHistory = [];

    reservations.forEach(reservation => {
      if (reservation.status === 'accepted') {
        const date = new Date(reservation.startDate);
        const month = date.getMonth() + 1; // Janvier = 1
        const year = date.getFullYear();
        
        // Total des gains
        totalEarnings += reservation.totalPrice;

        // Gains mensuels
        const monthKey = `${year}-${month}`;
        if (!monthlyEarnings[monthKey]) monthlyEarnings[monthKey] = 0;
        monthlyEarnings[monthKey] += reservation.totalPrice;

        // Gains annuels
        if (!yearlyEarnings[year]) yearlyEarnings[year] = 0;
        yearlyEarnings[year] += reservation.totalPrice;

        // Historique des réservations acceptées uniquement
        reservationHistory.push({
          listingTitle: reservation.listingId ? reservation.listingId.title : "Titre non disponible", // Vérifiez que listingId est bien peuplé
          startDate: reservation.startDate,
          endDate: reservation.endDate,
          totalPrice: reservation.totalPrice,
          status: reservation.status
        });
      }
    });

    // Transformer les gains mensuels et annuels en tableaux pour le frontend
    const monthlyEarningsArray = Object.entries(monthlyEarnings).map(([month, earnings]) => ({
      month,
      earnings
    }));
    
    const yearlyEarningsArray = Object.entries(yearlyEarnings).map(([year, earnings]) => ({
      year,
      earnings
    }));

    // Répondre avec les données de l'API
    res.json({
      totalEarnings,
      acceptedReservations: reservations.filter(r => r.status === 'accepted').length,
      monthlyEarnings: monthlyEarningsArray,
      yearlyEarnings: yearlyEarningsArray,
      reservationHistory
    });
  } catch (error) {
    console.error('Erreur lors du calcul des gains:', error);
    res.status(500).json({ error: 'Erreur lors du calcul des gains' });
  }
});

// Route pour générer une facture en PDF
app.get('/api/reservations/:id/invoice', async (req, res) => {
  try {
    const reservation = await Reservation.findById(req.params.id).populate('listingId userId');
    if (!reservation) return res.status(404).json({ error: 'Réservation non trouvée' });

    const doc = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=facture-${reservation._id}.pdf`);
    doc.pipe(res);

    doc.fontSize(20).text('Facture', { align: 'center' });
    doc.text(`\nRéservation pour ${reservation.listingId.title}`);
    doc.text(`Client : ${reservation.userId.firstName} ${reservation.userId.lastName}`);
    doc.text(`Dates : ${new Date(reservation.startDate).toLocaleDateString()} - ${new Date(reservation.endDate).toLocaleDateString()}`);
    doc.text(`Total : ${reservation.totalPrice} €`);

    doc.end();
  } catch (error) {
    console.error('Erreur lors de la génération de la facture:', error);
    res.status(500).json({ error: 'Erreur lors de la génération de la facture' });
  }
});

// Configuration de Nodemailer pour les emails de vérification
const transporter = nodemailer.createTransport({
  host: 'smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: '4f57f27653de4b', // Votre identifiant Mailtrap
    pass: 'dc1b3ac9079c35' // Votre mot de passe Mailtrap
  }
});

// Routes d'inscription et vérification par email
app.post('/api/verify-email', async (req, res) => {
  const { email, verificationCode } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(400).json({ error: 'Utilisateur non trouvé.' });
  }

  const now = new Date();
  const codeExpiry = new Date(user.codeGeneratedAt);
  codeExpiry.setMinutes(codeExpiry.getMinutes() + 10);

  if (user.verificationCode === verificationCode && now <= codeExpiry) {
    user.isEmailVerified = true;
    user.verificationCode = null;
    user.codeGeneratedAt = null;
    await user.save();

    // Générer le token JWT
    const token = jwt.sign({ userId: user._id }, 'Dadou6497', { expiresIn: '1h' });

    // Envoyer le message de succès et le token
    res.json({ message: 'Email vérifié avec succès.', token });
  } else {
    res.status(400).json({ error: 'Code de vérification invalide ou expiré.' });
  }
});

// Endpoint pour gérer les "cœurs"
app.post('/api/listings/:id/heart', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Non autorisé' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'Dadou6497');
    const userId = decoded.userId;

    const listingId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(listingId) || !mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'ID utilisateur ou logement invalide.' });
    }

    const listing = await Listing.findById(listingId);
    if (!listing) {
      return res.status(404).json({ error: 'Logement introuvable' });
    }

    // Ajouter ou retirer l'utilisateur des cœurs
    const index = listing.hearts.indexOf(userId);
    if (index > -1) {
      listing.hearts.splice(index, 1); // Retirer le like
    } else {
      listing.hearts.push(userId); // Ajouter le like
    }

    await listing.updateOne({ hearts: listing.hearts });

    res.json({
      hasHeart: index === -1, // Nouveau statut
      heartsCount: listing.hearts.length,
    });
  } catch (error) {
    console.error('Erreur lors de la gestion du cœur :', error);
    res.status(500).json({ error: 'Erreur serveur lors de la gestion du cœur.' });
  }
});



// Endpoint pour récupérer les favoris d'un utilisateur
app.get('/api/my-favorites', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Non autorisé.' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, 'Dadou6497');
    const userId = decoded.userId;

    // Vérifier les annonces likées par cet utilisateur
    const listings = await Listing.find({ hearts: userId });
    res.json(listings);
  } catch (error) {
    console.error('Erreur lors de la récupération des favoris :', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des favoris.' });
  }
});




  
// Démarrer le serveur
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

// Création d'un utilisateur administrateur si nécessaire
createAdminUser();
