// HABBINER SOARES DE ANDRADE

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const app = express();

// Dependências de segurança
const helmet = require('helmet');                 // cabeçalhos de segurança (CSP, etc.)
const { JSDOM } = require('jsdom');               // DOM virtual para usar DOMPurify no servidor
const createDOMPurify = require('dompurify');     // sanitização de HTML para evitar XSS

// Configuração do DOMPurify no servidor
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const db = new sqlite3.Database(':memory:');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Cria tabela de comentários e insere um comentário inicial
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao sistema de comentários')");
});

// Middleware que garante existência de cookie de sessão
// httpOnly definido para true para reduzir risco de exposição via JavaScript
app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        res.cookie('session_id', 'SESSION_PLACEHOLDER', {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'Strict'
        });
    }
    next();
});

// Configuração básica de Content Security Policy com Helmet
// Permite apenas recursos do mesmo domínio e bloqueia objetos externos
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      imgSrc: ["'self'", "data:"],
      upgradeInsecureRequests: []
    }
  })
);

// Rota principal: renderiza todos os comentários armazenados
app.get('/', (req, res) => {
    db.all("SELECT * FROM comments", [], (err, rows) => {
        if (err) {
            return res.send('Erro ao carregar comentários');
        }
        res.render('comments', { comments: rows });
    });
});

// Rota para enviar comentários
// Conteúdo é sanitizado no servidor antes de persistir para reduzir risco de XSS
app.post('/comment', (req, res) => {
    const { content } = req.body;

    const clean = DOMPurify.sanitize(content || '', {
      ALLOWED_TAGS: ['b','i','em','strong','a','p','br','ul','ol','li'],
      ALLOWED_ATTR: ['href','title']
    });

    db.run("INSERT INTO comments (content) VALUES (?)", [clean], (err) => {
        if (err) {
            return res.send('Erro ao salvar comentário');
        }
        res.redirect('/');
    });
});

// Inicializa o servidor
app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
