const mongoose = require('mongoose');
const faker = require('faker');

// Connexion à MongoDB
mongoose.connect('mongodb://localhost:27017/airbnb_clone', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  isEmailVerified: { type: Boolean, default: false },
  verificationCode: { type: String },
  codeGeneratedAt: { type: Date },
  username: { type: String, required: false, unique: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, unique: true },
  password: { type: String, required: true },
  phone: { type: String, required: false },
  address: { type: String, required: false },
  isAdmin: { type: Boolean, default: false },
  respectShabbat: { type: String, enum: ['Oui', 'Non'], required: true },
  respectKosher: { type: String, enum: ['Oui', 'Non'], required: true },
  kosherHecher: { type: String },
  role: { type: String, enum: ['voyageur', 'hébergeur'], required: true, default: 'voyageur' },
  isHost: { type: Boolean, default: false },
});

const User = mongoose.model('User', userSchema);

async function addRandomInfoToUsers() {
  try {
    const users = await User.find({}); // Récupère tous les documents

    for (const user of users) {
      let updated = false;

      // Ajout du prénom et du nom aléatoire si manquants
      if (!user.firstName) {
        user.firstName = faker.name.firstName();
        updated = true;
      }

      if (!user.lastName) {
        user.lastName = faker.name.lastName();
        updated = true;
      }

      // Ajout du username aléatoire si manquant
      if (!user.username) {
        user.username = faker.internet.userName(); // Génère un nom d'utilisateur aléatoire
        updated = true;
      }

      // Ajout de l'email aléatoire si manquant
      if (!user.email) {
        user.email = faker.internet.email(); // Génère un email aléatoire
        updated = true;
      }

      // Ajout du mot de passe par défaut si manquant (vous devriez sécuriser ceci dans un vrai cas)
      if (!user.password) {
        user.password = faker.internet.password(); // Génère un mot de passe aléatoire
        updated = true;
      }

      // Ajout du numéro de téléphone aléatoire si manquant
      if (!user.phone) {
        user.phone = faker.phone.phoneNumber(); // Génère un numéro de téléphone aléatoire
        updated = true;
      }

      // Ajout de l'adresse aléatoire si manquante
      if (!user.address) {
        user.address = faker.address.streetAddress(); // Génère une adresse aléatoire
        updated = true;
      }

      // Ajout des réponses du questionnaire (respectShabbat, respectKosher) si manquantes
      if (!user.respectShabbat) {
        user.respectShabbat = faker.random.arrayElement(['Oui', 'Non']); // Génère une réponse aléatoire
        updated = true;
      }

      if (!user.respectKosher) {
        user.respectKosher = faker.random.arrayElement(['Oui', 'Non']); // Génère une réponse aléatoire
        updated = true;
      }

      // Ajout de kosherHecher si manquant
      if (!user.kosherHecher) {
        user.kosherHecher = faker.lorem.word(); // Génère un mot aléatoire pour kosherHecher
        updated = true;
      }

      // Ajout de la role si manquante
      if (!user.role) {
        user.role = 'voyageur'; // Par défaut, "voyageur"
        updated = true;
      }

      // Ajout de isHost si manquant
      if (user.role === 'hébergeur' && !user.isHost) {
        user.isHost = true; // Si le rôle est hébergeur, on définit isHost à true
        updated = true;
      }

      // Si des informations ont été ajoutées ou mises à jour, on enregistre le document
      if (updated) {
        await user.save(); // Enregistre les modifications
        console.log(`Mise à jour de l'utilisateur ID: ${user._id}`);
      }
    }

    console.log('Ajout des informations manquantes dans les utilisateurs terminé.');
  } catch (error) {
    console.error('Erreur lors de l\'ajout des informations manquantes:', error);
  } finally {
    mongoose.connection.close(); // Ferme la connexion à MongoDB après la mise à jour
  }
}

addRandomInfoToUsers();
