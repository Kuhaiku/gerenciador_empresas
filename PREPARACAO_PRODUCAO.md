# GUIA DE TRANSIÇÃO PARA PRODUÇÃO (STRIPE E EASYPANEL)

Este guia detalha os passos necessários para tirar a aplicação do "Modo de Teste" e iniciar a cobrança de pagamentos reais usando o Stripe na URL: `https://www-gerenciadorempresas-app.velmc0.easypanel.host/`.

## 1. Configuração de Credenciais de Produção (Stripe)

A área de Teste (sk_test_) e Produção (sk_live_) do Stripe são totalmente separadas. Você precisa criar um novo Plano e obter as chaves ativas.

### 1.1. Obter Chaves Ativas

1.  Acesse o **Dashboard do Stripe**.
2.  No canto superior esquerdo, **DESATIVE** o botão "Visualizar dados de teste".
3.  Vá para **Desenvolvedores** > **Chaves de API**.
4.  Copie a **Chave Secreta do modo de produção** (começa com `sk_live_...`).

### 1.2. Criar Plano de Produção

1.  Ainda no modo de Produção (Live Mode) do Stripe, vá para **Faturamento** > **Produtos**.
2.  Crie o produto e o preço de R$ 60,00 **novamente**.
    * **Produto:** Assinatura Mensal - Gerenciador de Empresas
    * **Preço:** R$ 60,00, Mensal
3.  Copie o **ID do Preço** recém-criado. Este será o seu `STRIPE_PRICE_ID` de produção (começa com `price_...`).

## 2. Configuração do Easypanel (Variáveis de Ambiente)

O seu `.env` nunca deve ser enviado. Em vez disso, você deve configurar as variáveis diretamente no painel do Easypanel.

1.  Acesse o Painel do Easypanel e vá para as configurações de ambiente da sua aplicação.
2.  Substitua os valores de TESTE pelos de PRODUÇÃO:

| Variável | Valor de Produção | Origem |
| :--- | :--- | :--- |
| `STRIPE_SECRET_KEY` | `sk_live_...` | Chave copiada em 1.1 |
| `STRIPE_PRICE_ID` | `price_...` | ID copiado em 1.2 |
| `BASE_URL` | `https://www-gerenciadorempresas-app.velmc0.easypanel.host` | URL do Easypanel |
| `DB_HOST`, `DB_USER`, etc. | Credenciais do seu DB de produção | Seu serviço de banco de dados |

## 3. Implementação de Webhooks (CRUCIAL PARA PRODUÇÃO)

Em produção, pagamentos assíncronos (Boleto) e eventos de cancelamento exigem o Webhook para manter o status do seu DB sincronizado.

### 3.1. Adicionar Rota de Webhook ao `server.js`

Você precisa adicionar uma rota para o Stripe notificar sua aplicação. Mantenha as outras rotas (como `app.get('/subscription/success')`) intactas, mas adicione esta:

**(Adicione este bloco ao seu `server.js`)**

```javascript
// ---------------- STRIPE: ROTA DE WEBHOOK ----------------
// Adicione o body-parser.raw, ele é essencial para a verificação de assinatura do Webhook
app.post('/stripe-webhook', bodyParser.raw({type: 'application/json'}), async (req, res) => {
    const signature = req.headers['stripe-signature'];
    let event;

    // É altamente recomendado configurar o STRIPE_WEBHOOK_SECRET no seu Easypanel.
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

    try {
        event = stripeClient.webhooks.constructEvent(req.body, signature, endpointSecret);
    } catch (err) {
        console.error(`⚠️ Webhook signature verification failed.`, err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    const connection = await createDBConnection();

    try {
        // Tratar os eventos mais importantes para assinaturas
        switch (event.type) {
            case 'customer.subscription.deleted':
            case 'customer.subscription.updated':
                const subscription = event.data.object;
                const status = subscription.status === 'active' ? 'active' : 'inactive'; // Simplificado
                const customerId = subscription.customer;

                // Encontre o usuário pelo customerId e atualize o subscription_status no DB
                await connection.execute(
                    'UPDATE users SET subscription_status = ? WHERE stripe_customer_id = ?',
                    [status, customerId]
                );
                console.log(`[WEBHOOK] Assinatura atualizada para status: ${status} para o cliente ${customerId}`);
                break;
            case 'checkout.session.completed':
                // Se você não confia apenas no /subscription/success, este evento é o mais seguro para ativar.
                // Mas seu /subscription/success já cuida disso.
                break;
            default:
                console.log(`[WEBHOOK] Evento não tratado: ${event.type}`);
        }
    } catch (error) {
        console.error('Erro no processamento do Webhook:', error);
        return res.status(500).send('Erro no Servidor ao processar evento.');
    } finally {
        connection.end();
    }

    res.status(200).send('OK');
});

4. Ajuste Final de Código (Segurança)
Altere o seu server.js para garantir que o cookie de sessão seja seguro em HTTPS:

(No bloco app.use(session({...})) de server.js)

JavaScript

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  // Mudar para TRUE em produção (EasyPanel usa HTTPS)
  cookie: { secure: true, maxAge: 3600000 } 
}));