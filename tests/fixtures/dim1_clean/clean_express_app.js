// tests/fixtures/dim1_clean/clean_express_app.js
// 正常程式碼 — Express + helmet + parameterized MongoDB query

const express = require('express');
const helmet = require('helmet');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.use(helmet());
app.use(express.json());

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = 'myapp';

async function getDb() {
  const client = await MongoClient.connect(MONGO_URI);
  return client.db(DB_NAME);
}

// 安全：使用 ObjectId 驗證 + 無字串拼接
app.get('/api/users/:id', async (req, res) => {
  try {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ error: 'Invalid ID format' });
    }
    const db = await getDb();
    const user = await db.collection('users').findOne({
      _id: new ObjectId(req.params.id)
    });
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ id: user._id, name: user.name, email: user.email });
  } catch (err) {
    console.error('DB error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 安全：輸入長度限制 + 白名單欄位
app.post('/api/users', async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Missing fields' });
  if (name.length > 100 || email.length > 200) {
    return res.status(400).json({ error: 'Input too long' });
  }

  const db = await getDb();
  const result = await db.collection('users').insertOne({ name, email });
  res.status(201).json({ id: result.insertedId });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
