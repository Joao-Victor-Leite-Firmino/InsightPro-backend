const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const app = express();
const db = new sqlite3.Database('InsightPro.db'); // Para persistência
const SECRET_KEY = 'seu_segredo_jwt'; // Altere para uma chave segura

app.use(express.json());
app.use(cors()); // Permite acesso ao backend de outros domínios

// Criação das tabelas
db.serialize(() => {
  // Tabela de usuários
  db.run(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      password TEXT,
      empresa TEXT
    )
  `);

  // Tabela de produtos
  db.run(`
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      company TEXT,
      average_rating TEXT
    )
  `);

  // Tabela de comentários
  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER,
      comment TEXT,
      FOREIGN KEY (product_id) REFERENCES products(id)
    )
  `);
});

// Registro de um novo usuário
app.post('/registro', async (req, res) => {
  const { email, password, company } = req.body;

  if (!email || !password || !company) {
    return res.status(400).json({ message: 'Por favor, preencha todos os campos.' });
  }

  try {
    // Verifica se o usuário já existe
    db.get('SELECT email FROM usuarios WHERE email = ?', [email], async (err, row) => {
      if (row) {
        return res.status(400).json({ message: 'E-mail já registrado.' });
      }

      // Hash da senha
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insere o novo usuário
      db.run('INSERT INTO usuarios (email, password, company) VALUES (?, ?, ?)', [email, hashedPassword, company], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Erro ao registrar o usuário.' });
        }

        res.status(201).json({ message: 'Usuário registrado com sucesso!' });
      });
    });
  } catch (error) {
    res.status(500).json({ message: 'Erro no servidor.' });
  }
});

// Login de um usuário existente
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Por favor, preencha todos os campos.' });
  }

  db.get('SELECT * FROM usuarios WHERE email = ?', [email], async (err, user) => {
    if (!user) {
      return res.status(400).json({ message: 'Usuário não encontrado.' });
    }

    // Verifica a senha
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Credenciais inválidas.' });
    }

    // Gera o token JWT
    const token = jwt.sign({ email: user.email, company: user.company }, SECRET_KEY, { expiresIn: '1h' });
    
    res.json({ token, company: user.company });
  });
});

// Middleware de autenticação para proteger rotas
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Token não fornecido.' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido.' });
    req.user = user;
    next();
  });
};

// Rota para salvar os dados do produto e comentários
app.post('/saveProductData', (req, res) => {
  const { name, company, average_rating, comments } = req.body;

  if (!name || !company || !average_rating || !comments) {
    return res.status(400).json({ message: 'Dados incompletos.' });
  }

  // Inserir produto no banco de dados
  db.run('INSERT INTO products (name, company, average_rating) VALUES (?, ?, ?)', [name, company, average_rating], function(err) {
    if (err) {
      return res.status(500).json({ message: 'Erro ao salvar o produto.' });
    }

    const productId = this.lastID;

    // Inserir comentários associados ao produto
    const insertComment = db.prepare('INSERT INTO comments (product_id, comment) VALUES (?, ?)');
    comments.forEach((comment) => {
      insertComment.run(productId, comment);
    });
    insertComment.finalize();

    res.status(201).json({ message: 'Produto e comentários salvos com sucesso!' });
  });
});

// Rota para buscar todos os produtos e seus comentários
app.get('/products', (req, res) => {
  db.all('SELECT * FROM products', (err, products) => {
    if (err) {
      return res.status(500).json({ message: 'Erro ao buscar produtos.' });
    }

    // Itera sobre cada produto e busca seus comentários
    const productsWithComments = products.map((product) => {
      return new Promise((resolve, reject) => {
        db.all('SELECT comment FROM comments WHERE product_id = ?', [product.id], (err, comments) => {
          if (err) {
            reject(err);
          } else {
            product.comments = comments.map(c => ({ id: c.id, text: c.comment }));
            resolve(product);
          }
        });
      });
    });

    Promise.all(productsWithComments)
      .then(results => res.json(results))
      .catch(error => res.status(500).json({ message: 'Erro ao buscar comentários dos produtos.' }));
  });
});

// Rota para buscar detalhes de um produto por ID
app.get('/products/:id', (req, res) => {
  const productId = req.params.id;

  db.get('SELECT * FROM products WHERE id = ?', [productId], (err, product) => {
    if (err) {
      return res.status(500).json({ message: 'Erro ao buscar produto.' });
    }

    if (!product) {
      return res.status(404).json({ message: 'Produto não encontrado.' });
    }

    // Busca os comentários associados ao produto
    db.all('SELECT comment FROM comments WHERE product_id = ?', [productId], (err, comments) => {
      if (err) {
        return res.status(500).json({ message: 'Erro ao buscar comentários.' });
      }

      // Adiciona os comentários ao produto e retorna a resposta
      product.comments = comments.map(c => ({ id: c.id, text: c.comment }));
      res.json(product);
    });
  });
});

// Rota para excluir um produto por ID
app.delete('/deleteProduct/:id', (req, res) => {
  const productId = req.params.id;

  const query = `DELETE FROM products WHERE id = ?`;

  db.run(query, [productId], function (err) {
    if (err) {
      console.error("Erro ao excluir o produto:", err);
      return res.status(500).json({ error: "Erro ao excluir o produto" });
    }

    if (this.changes > 0) {
      res.status(200).json({ message: `Produto com ID ${productId} excluído com sucesso` });
    } else {
      res.status(404).json({ error: `Produto com ID ${productId} não encontrado` });
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
