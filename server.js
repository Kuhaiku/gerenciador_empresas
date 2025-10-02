// ---------------- IMPORTAÇÕES ----------------
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
// NOVO: Importação do Stripe
const stripe = require('stripe');

// ---------------- CONFIGURAÇÕES ----------------
const app = express();
const port = 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT
};

async function createDBConnection() {
  try {
    const connection = await mysql.createConnection(dbConfig);
    console.log('Conectado ao MySQL.');
    return connection;
  } catch (error) {
    console.error('Erro ao conectar MySQL:', error);
    throw error;
  }
}

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_PORT == 465,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, maxAge: 3600000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

// ---------------- STRIPE ----------------
const stripeClient = stripe(process.env.STRIPE_SECRET_KEY);
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID;

// ---------------- ROTAS PÁGINAS ----------------
app.get('/', (req, res) => {
  const message = req.session.message;
  req.session.message = null;
  res.render('login', { message });
});

app.get('/register', (req, res) => {
  const message = req.session.message;
  req.session.message = null;
  res.render('register', { message });
});

app.get('/verify-email', (req, res) => {
  const message = req.session.message;
  req.session.message = null;
  res.render('verify_email', { message });
});

app.get('/dashboard', async (req, res) => {
  if (!req.session.loggedin) {
    req.session.message = 'Faça login para acessar o dashboard.';
    return res.redirect('/');
  }

  const connection = await createDBConnection();
  const [rows] = await connection.execute(
    'SELECT subscription_status FROM users WHERE email = ?',
    [req.session.email]
  );
  const subscriptionStatus = rows[0] ? rows[0].subscription_status : 'inactive';
  connection.end();

  const message = req.session.message || null;
  req.session.message = null;
  res.render('dashboard', { message, email: req.session.email, subscriptionStatus });
});

app.get('/forgot-password', (req, res) => {
  const message = req.session.message;
  req.session.message = null;
  res.render('forgot_password', { message });
});

app.get('/reset-password', (req, res) => {
  const message = req.session.message;
  req.session.message = null;
  res.render('reset_password', { message });
});

app.get('/subscription', (req, res) => {
  if (!req.session.loggedin) {
    req.session.message = 'Faça login para assinar.';
    return res.redirect('/');
  }
  const message = req.session.message || null;
  req.session.message = null;
  res.render('subscription', { message });
});

// ---------------- AUTENTICAÇÃO (Sem alterações) ----------------

// Registro
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const connection = await createDBConnection();

  try {
    const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length > 0) {
      req.session.message = 'Este e-mail já está em uso.';
      return res.redirect('/register');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const verificationToken = await bcrypt.hash(code, 10);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await connection.execute(
      'INSERT INTO users (email, password, verification_code, verification_expires_at) VALUES (?, ?, ?, ?)',
      [email, hashedPassword, verificationToken, expiresAt]
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Código de Verificação de Conta',
      html: `<h2>Seu código de verificação</h2><p>${code}</p>`
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.log(err);
        req.session.message = 'Erro ao enviar e-mail.';
        return res.redirect('/register');
      }
      req.session.message = 'Verifique seu e-mail para ativar a conta.';
      res.redirect('/verify-email');
    });
  } catch (error) {
    console.error(error);
    req.session.message = 'Erro no servidor.';
    res.redirect('/register');
  } finally {
    connection.end();
  }
});

// Verificação de e-mail
app.post('/verify-email', async (req, res) => {
  const { email, code } = req.body;
  const connection = await createDBConnection();

  try {
    const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      req.session.message = 'E-mail não encontrado.';
      return res.redirect('/verify-email');
    }

    const user = rows[0];
    if (new Date() > user.verification_expires_at) {
      req.session.message = 'Código expirado. Registre-se novamente.';
      return res.redirect('/register');
    }

    const isMatch = await bcrypt.compare(code, user.verification_code);
    if (isMatch) {
      await connection.execute(
        'UPDATE users SET verified = 1, verification_code = NULL, verification_expires_at = NULL WHERE email = ?',
        [email]
      );
      req.session.message = 'E-mail verificado. Faça login.';
      res.redirect('/');
    } else {
      req.session.message = 'Código inválido.';
      res.redirect('/verify-email');
    }
  } catch (error) {
    console.error(error);
    req.session.message = 'Erro no servidor.';
    res.redirect('/verify-email');
  } finally {
    connection.end();
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const connection = await createDBConnection();

  try {
    const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      req.session.message = 'E-mail ou senha incorretos.';
      return res.redirect('/');
    }

    const user = rows[0];
    if (!user.verified) {
      req.session.message = 'Conta não verificada.';
      return res.redirect('/');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      req.session.loggedin = true;
      req.session.email = email;
      req.session.message = 'Bem-vindo!';
      res.redirect('/dashboard');
    } else {
      req.session.message = 'E-mail ou senha incorretos.';
      res.redirect('/');
    }
  } catch (error) {
    console.error(error);
    req.session.message = 'Erro no servidor.';
    res.redirect('/');
  } finally {
    connection.end();
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error(err);
    res.redirect('/');
  });
});

// Recuperação de Senha - Enviar Código (usando 'reset_token')
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const connection = await createDBConnection();

  try {
    const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      req.session.message = 'E-mail não encontrado.';
      return res.redirect('/forgot-password');
    }

    const user = rows[0];
    if (!user.verified) {
      req.session.message = 'Conta não verificada. Por favor, verifique seu e-mail primeiro.';
      return res.redirect('/forgot-password');
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const resetToken = await bcrypt.hash(code, 10);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hora de validade

    await connection.execute(
      'UPDATE users SET reset_token = ?, reset_expires_at = ? WHERE email = ?',
      [resetToken, expiresAt, email]
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Código de Recuperação de Senha',
      html: `<h2>Seu código de recuperação</h2><p>${code}</p><p>Este código é válido por 1 hora.</p>`
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error(err);
        req.session.message = 'Erro ao enviar e-mail com código de recuperação.';
        return res.redirect('/forgot-password');
      }
      req.session.message = 'Código de recuperação enviado para o seu e-mail.';
      res.redirect('/reset-password');
    });

  } catch (error) {
    console.error(error);
    req.session.message = 'Erro no servidor ao solicitar recuperação.';
    res.redirect('/forgot-password');
  } finally {
    connection.end();
  }
});

// Redefinir Senha (usando 'reset_token')
app.post('/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;
  const connection = await createDBConnection();

  try {
    const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      req.session.message = 'E-mail não encontrado.';
      return res.redirect('/reset-password');
    }

    const user = rows[0];
    
    if (!user.reset_token || new Date() > user.reset_expires_at) {
      req.session.message = 'Código inválido ou expirado. Tente solicitar um novo código.';
      return res.redirect('/forgot-password');
    }

    const isMatch = await bcrypt.compare(code, user.reset_token);
    
    if (isMatch) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      
      await connection.execute(
        'UPDATE users SET password = ?, reset_token = NULL, reset_expires_at = NULL WHERE email = ?',
        [hashedPassword, email]
      );
      
      req.session.message = 'Senha redefinida com sucesso! Faça login.';
      res.redirect('/');
    } else {
      req.session.message = 'Código inválido.';
      res.redirect('/reset-password');
    }

  } catch (error) {
    console.error(error);
    req.session.message = 'Erro no servidor ao redefinir senha.';
    res.redirect('/reset-password');
  } finally {
    connection.end();
  }
});


// ---------------- STRIPE: Criar Checkout Session (Assinatura) ----------------

app.post('/create-subscription', async (req, res) => {
  if (!req.session.loggedin || !req.session.email) {
    req.session.message = 'Faça login para assinar.';
    return res.redirect('/');
  }

  const userEmail = req.session.email;
  const connection = await createDBConnection();

  try {
    const [rows] = await connection.execute(
      'SELECT stripe_customer_id, subscription_status FROM users WHERE email = ?', 
      [userEmail]
    );
    const user = rows[0];

    if (!user) {
      req.session.message = 'Usuário não encontrado.';
      return res.redirect('/dashboard');
    }

    // 1. Obter ou Criar Cliente Stripe
    let stripeCustomerId = user.stripe_customer_id;
    if (!stripeCustomerId) {
      const customer = await stripeClient.customers.create({
        email: userEmail,
        metadata: { userId: userEmail }
      });
      stripeCustomerId = customer.id;

      // Salvar o novo customer ID no DB
      await connection.execute(
        'UPDATE users SET stripe_customer_id = ? WHERE email = ?',
        [stripeCustomerId, userEmail]
      );
    }
    
    // 2. Criar a Stripe Checkout Session
    const session = await stripeClient.checkout.sessions.create({
      // CORREÇÃO: Usando apenas métodos ativados (cartão e boleto) para evitar o erro de Pix
      payment_method_types: ['card', 'boleto'], 
      mode: 'subscription',
      line_items: [
        {
          price: STRIPE_PRICE_ID,
          quantity: 1,
        },
      ],
      customer: stripeCustomerId,
      // URL de Sucesso: Retorna para o nosso endpoint para verificar a sessão
      success_url: process.env.BASE_URL + '/subscription/success?session_id={CHECKOUT_SESSION_ID}',
      cancel_url: process.env.BASE_URL + '/subscription',
      locale: 'pt'
    });

    // 3. Redirecionar para o Checkout do Stripe
    res.redirect(303, session.url);

  } catch (err) {
    console.error('Erro ao criar Checkout Session do Stripe:', err);
    req.session.message = 'Erro ao criar sessão de pagamento.';
    res.redirect('/subscription');
  } finally {
    connection.end();
  }
});

// ---------------- STRIPE: Callback de Sucesso ----------------

app.get('/subscription/success', async (req, res) => {
  if (!req.session.loggedin) {
    return res.redirect('/');
  }

  const sessionId = req.query.session_id;
  const connection = await createDBConnection();

  try {
    // 1. Obter a sessão do Stripe
    const session = await stripeClient.checkout.sessions.retrieve(sessionId);

    if (session.payment_status === 'paid' && session.mode === 'subscription') {
      const subscriptionId = session.subscription;
      
      // 2. Atualizar o status do usuário no DB
      await connection.execute(
        'UPDATE users SET subscription_status = ?, stripe_subscription_id = ? WHERE email = ?',
        ['active', subscriptionId, req.session.email]
      );
      
      req.session.message = 'Assinatura ativada com sucesso! Bem-vindo.';
    } else if (session.payment_status === 'unpaid' || session.status === 'open') {
      req.session.message = 'Pagamento pendente. Sua assinatura será ativada em breve.';
    } else {
      req.session.message = 'Problema no pagamento. Tente novamente.';
    }

  } catch (err) {
    // Captura qualquer erro de conexão com DB ou Stripe
    console.error('Erro ao verificar Stripe Session:', err);
    req.session.message = 'Erro ao finalizar a assinatura.';
  } finally {
    // SEMPRE FECHA A CONEXÃO
    connection.end();
  }
  
  // GARANTE O REDIRECIONAMENTO HTTP APÓS A CONCLUSÃO DA LÓGICA
  res.redirect('/dashboard'); 
});

// ---------------- INICIAR SERVIDOR ----------------
app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});