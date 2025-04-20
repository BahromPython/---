const fs = require('fs');
const path = require('path');

// Проверка и создание файла .env
const envPath = path.join(__dirname, '.env');
const envTemplate = `
# Параметры подключения к PostgreSQL
DB_USER=postgres
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=video_platform

# Параметры AWS S3 для хранения видео
AWS_ACCESS_KEY=your_aws_access_key
AWS_SECRET_KEY=your_aws_secret_key
AWS_REGION=your_aws_region
AWS_BUCKET=your_aws_bucket_name

# Секретный ключ для JWT (аутентификация)
JWT_SECRET=your_jwt_secret

# Ключ Stripe для обработки платежей
STRIPE_SECRET_KEY=your_stripe_secret_key
`;

if (!fs.existsSync(envPath)) {
  fs.writeFileSync(envPath, envTemplate);
  console.log('Файл .env создан. Пожалуйста, заполните его вашими данными и перезапустите сервер.');
  process.exit(1);
}

// Загрузка переменных окружения
require('dotenv').config();

// Проверка обязательных переменных
const requiredEnvVars = [
  'DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_PORT', 'DB_NAME',
  'AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'AWS_REGION', 'AWS_BUCKET',
  'JWT_SECRET', 'STRIPE_SECRET_KEY'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar] || process.env[envVar].startsWith('your_')) {
    console.error(`Ошибка: Переменная окружения ${envVar} не задана или содержит значение по умолчанию. Пожалуйста, настройте .env.`);
    process.exit(1);
  }
}

const express = require('express');
const { Pool } = require('pg');
const AWS = require('aws-sdk');
const multer = require('multer');
const ffmpeg = require('fluent-ffmpeg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const WebSocket = require('ws');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const upload = multer({ dest: 'uploads/' });
app.use(cors());
app.use(express.json());

// Настройка базы данных
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// Настройка AWS S3
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_KEY,
  region: process.env.AWS_REGION,
});

// Middleware для проверки токена
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Регистрация пользователя
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id',
      [username, hashedPassword]
    );
    res.json({ id: result.rows[0].id });
  } catch (err) {
    res.status(400).json({ error: 'Username already exists' });
  }
});

// Вход пользователя
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
  res.json({ token });
});

// Загрузка видео
app.post('/upload', authenticateToken, upload.single('video'), async (req, res) => {
  const file = req.file;
  const userId = req.user.id;
  const outputPath = `processed-${file.filename}.mp4`;

  ffmpeg(file.path)
    .outputOptions('-vf', 'scale=1280:720')
    .save(outputPath)
    .on('end', async () => {
      const s3Params = {
        Bucket: process.env.AWS_BUCKET,
        Key: `videos/${outputPath}`,
        Body: fs.createReadStream(outputPath),
        ContentType: 'video/mp4',
      };
      const s3Response = await s3.upload(s3Params).promise();

      await pool.query(
        'INSERT INTO videos (user_id, title, file_url) VALUES ($1, $2, $3)',
        [userId, req.body.title, s3Response.Location]
      );

      fs.unlinkSync(file.path);
      fs.unlinkSync(outputPath);
      res.json({ message: 'Video uploaded', url: s3Response.Location });
    })
    .on('error', (err) => res.status(500).json({ error: err.message }));
});

// Получение списка видео
app.get('/videos', async (req, res) => {
  const result = await pool.query('SELECT * FROM videos ORDER BY created_at DESC');
  res.json(result.rows);
});

// Добавление комментария
app.post('/comment', authenticateToken, async (req, res) => {
  const { videoId, content } = req.body;
  await pool.query(
    'INSERT INTO comments (video_id, user_id, content) VALUES ($1, $2, $3)',
    [videoId, req.user.id, content]
  );
  res.json({ message: 'Comment added' });
});

// Получение комментариев
app.get('/comments/:videoId', async (req, res) => {
  const result = await pool.query('SELECT * FROM comments WHERE video_id = $1', [req.params.videoId]);
  res.json(result.rows);
});

// Создание платежа через Stripe
app.post('/create-payment-intent', authenticateToken, async (req, res) => {
  const { amount } = req.body;
  const paymentIntent = await stripe.paymentIntents.create({
    amount,
    currency: 'usd',
  });
  res.json({ clientSecret: paymentIntent.client_secret });
});

// Запуск сервера
const server = app.listen(5000, () => console.log('Server running on port 5000'));

// WebSocket для чата
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  ws.on('message', (message) => {
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message.toString());
      }
    });
  });
});