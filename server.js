const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

// Conexão com o banco de dados SQLite
const db = new sqlite3.Database('InsightPro.db');

// Criação das tabelas
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, company TEXT);");
    db.run("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, company TEXT, average_rating REAL, comments TEXT)");
});

app.use(express.json());
app.use(cors());

// Middleware para verificar o token JWT
const verificarToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ error: 'Nenhum token fornecido.' });
    }
    jwt.verify(token.split(' ')[1], 'secreto', (err, decoded) => {
        if (err) {
            return res.status(500).json({ error: 'Falha ao autenticar o token.' });
        }
        req.userId = decoded.id;
        req.userRole = decoded.role;
        next();
    });
};

// Endpoints para produtos
app.post('/products', (req, res) => {
    const { name, company, average_rating, comments } = req.body;
    if (!name || !company) {
        return res.status(400).json({ error: 'Nome e empresa são obrigatórios!' });
    }
    db.run("INSERT INTO products (name, company, average_rating, comments) VALUES (?, ?, ?, ?)", [name, company, average_rating, comments], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ id: this.lastID, name, company, average_rating, comments });
    });
});

app.get('/products', (req, res) => {
    db.all("SELECT * FROM products", [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json(rows);
    });
});

app.get('/products/:id', (req, res) => {
    const { id } = req.params;
    db.get("SELECT * FROM products WHERE id = ?", [id], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (row) {
            res.status(200).json(row);
        } else {
            res.status(404).json({ error: 'Produto não encontrado!' });
        }
    });
});

app.put('/products/:id', (req, res) => {
    const { id } = req.params;
    const { name, company, average_rating, comments } = req.body;
    if (!name && !company && average_rating === undefined && comments === undefined) {
        return res.status(400).json({ error: 'Pelo menos um campo deve ser fornecido para atualização!' });
    }

    const updateFields = [];
    const updateValues = [];

    if (name) {
        updateFields.push("name = ?");
        updateValues.push(name);
    }
    if (company) {
        updateFields.push("company = ?");
        updateValues.push(company);
    }
    if (average_rating !== undefined) {
        updateFields.push("average_rating = ?");
        updateValues.push(average_rating);
    }
    if (comments !== undefined) {
        updateFields.push("comments = ?");
        updateValues.push(comments);
    }

    updateValues.push(id);

    const query = `UPDATE products SET ${updateFields.join(", ")} WHERE id = ?`;

    db.run(query, updateValues, function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes) {
            res.status(200).json({ message: 'Produto atualizado com sucesso!' });
        } else {
            res.status(404).json({ error: 'Produto não encontrado!' });
        }
    });
});

app.delete('/products/:id', (req, res) => {
    const { id } = req.params;
    db.run("DELETE FROM products WHERE id = ?", [id], function (err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes) {
            res.status(200).json({ message: 'Produto removido com sucesso!' });
        } else {
            res.status(404).json({ error: 'Produto não encontrado!' });
        }
    });
});

// Endpoints para registro e login de usuários
app.post('/registro', async (req, res) => {
    const { email, password, company } = req.body;
    try {
        const usuarioExistente = await buscarUsuario(email);
        if (usuarioExistente) {
            return res.status(400).json({ error: 'Usuário já registrado' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await criarUsuario(email, hashedPassword, company);
        res.status(201).json({ message: 'Usuário registrado com sucesso' });
    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({ error: 'Erro no registro de usuário' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const usuario = await buscarUsuario(email);
        if (!usuario) {
            return res.status(401).json({ error: 'Usuário não encontrado' });
        }
        const senhaValida = await bcrypt.compare(password, usuario.password);
        if (!senhaValida) {
            return res.status(401).json({ error: 'Senha incorreta' });
        }
        const token = jwt.sign({ id: usuario.id, email: usuario.email, company: usuario.company }, 'secreto', { expiresIn: '1h' });
        res.status(200).json({ token });
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro no login de usuário' });
    }
});

// Funções auxiliares para manipulação de usuários
const buscarUsuario = (email) => {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM usuarios WHERE email = ?', [email], (err, row) => {
            if (err) {
                reject(err);
            }
            resolve(row);
        });
    });
};

const criarUsuario = (email, password, company) => {
    return new Promise((resolve, reject) => {
        db.run('INSERT INTO usuarios (email, password, company) VALUES (?, ?, ?)', [email, password, company], (err) => {
            if (err) {
                reject(err);
            }
            resolve();
        });
    });
};

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta http://localhost:${PORT}`);
});
