const mongoose = require('mongoose');
const faker = require('faker'); // Utilisation de faker.js pour générer des données aléatoires

// Définir le modèle Listing
const listingSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true, min: 0 },
  adresse: String,
  rue: String,
  ville: String,
  codePostal: String,
  pays: String,
  chambre: { type: Number, required: true, min: 1 },
  lit: { type: Number, required: true, min: 1 },
  litEnfantd: { type: Number, min: 0, default: 0 },
  guests: { type: Number, required: true, min: 1 },
  couchages: [{
    type: { type: String, enum: ['chambre', 'salon'], required: true },
    canapeLit: { type: Number, min: 0, default: 0 },
    litSimple: { type: Number, min: 0, default: 0 },
    litDouble: { type: Number, min: 0, default: 0 },
    litEnfant: { type: Number, min: 0, default: 0 }
  }],
  images: {
    type: [String],
    validate: [arrayLimit, '{PATH} doit contenir au moins une image']
  },
  amenities: [String],
  logement: String,
  logementType: String,
  hostFirstName: String,
  hostLastName: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  kosherValidation: Date,
  status: { type: String, default: 'pending' },
  availability: [{
    date: { type: Date, required: true },
    price: { type: Number, required: true, default: 0 },
    available: { type: Boolean, default: false },
    notes: String
  }],
  hearts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });

// Fonction de validation pour le tableau d'images
function arrayLimit(val) {
  return val.length > 0; // Vérifie que le tableau contient au moins une image
}

// Création du modèle
const Listing = mongoose.model('Listing', listingSchema);

// Connexion à la base de données MongoDB
mongoose.connect('mongodb://localhost:27017/airbnb_clone', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connexion réussie à la base de données');
}).catch(err => {
  console.error('Erreur de connexion à la base de données:', err);
});

// Fonction pour mettre à jour les annonces
const updateListings = async () => {
  try {
    const listings = await Listing.find({}); // Récupérer toutes les annonces

    // Parcourir chaque annonce pour ajouter des données aléatoires et supprimer les champs inutiles
    for (const listing of listings) {
      console.log(`Mise à jour de l'annonce avec id: ${listing._id}`);

      // Ajout de données aléatoires si les champs sont vides
      if (!listing.title) listing.title = faker.lorem.sentence();
      if (!listing.description) listing.description = faker.lorem.paragraph();
      if (listing.price === undefined) listing.price = faker.random.number({ min: 50, max: 500 });
      if (!listing.adresse) listing.adresse = faker.address.streetAddress();
      if (!listing.rue) listing.rue = faker.address.streetName();
      if (!listing.ville) listing.ville = faker.address.city();
      if (!listing.codePostal) listing.codePostal = faker.address.zipCode();
      if (!listing.pays) listing.pays = faker.address.country();
      if (listing.chambre === undefined) listing.chambre = faker.random.number({ min: 1, max: 5 });
      if (listing.lit === undefined) listing.lit = faker.random.number({ min: 1, max: 5 });
      if (listing.litEnfantd === undefined) listing.litEnfantd = faker.random.number({ min: 0, max: 3 });
      if (listing.guests === undefined) listing.guests = faker.random.number({ min: 1, max: 12 });

      // Ajouter une pièce salon avec canapé-lit si le tableau couchages est vide
      if (!listing.couchages || listing.couchages.length === 0) {
        listing.couchages = [{
          type: 'salon',
          canapeLit: faker.random.number({ min: 1, max: 2 }), // Minimum 1 canapé-lit
          litSimple: 0,
          litDouble: 0,
          litEnfant: 0,
        }];
      }

      // Ajouter des images aléatoires si non définies
      if (!listing.images || listing.images.length === 0) {
        listing.images = [faker.image.imageUrl(), faker.image.imageUrl(), faker.image.imageUrl()];
      }

      // Ajouter des commodités si non définies
      if (!listing.amenities || listing.amenities.length === 0) {
        listing.amenities = ['Wi-Fi', 'Climatisation', 'Télévision'];
      }

      // Si "kosherValidation" est manquant, on peut y ajouter une date aléatoire
      if (!listing.kosherValidation) listing.kosherValidation = faker.date.past();

      // Mise à jour du statut si nécessaire
      if (!listing.status) listing.status = 'pending';

      // Mise à jour des données dans la base
      await listing.save();
      console.log(`Annonce mise à jour avec succès: ${listing._id}`);
    }

    console.log('Mise à jour des annonces terminée!');
  } catch (err) {
    console.error('Erreur lors de la mise à jour des annonces:', err);
  } finally {
    mongoose.disconnect();
  }
};

// Lancer la mise à jour
updateListings();
