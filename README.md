[JWT.IO](https://www.jwt.io/)

### Json web token

Json Web Token → Um padrão de mercado que define um token no formato JSON para a troca de informação segura e compacta

![image.png](attachment:592f5c6d-5758-49b6-920e-a57191626e5e:image.png)

![image.png](attachment:c62a479c-117f-4a56-8999-00891ae89783:image.png)

**Onde usar o JWT?**

Por exemplo, em um cenário de autorização. Depois que o usuário estiver conectado, é possível observar cada requisição e verificar se inclui o JWT e verificando se o usuário tem autorização para acessar o recursos da API

Token:**`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3VzdGF2b2Vsb2kiLCJlbWFpbCI6Imd1c3Rhdm9vZWxvaUBnbWFpbC5jb20iLCJhZG1pbiI6ZmFsc2V9.UUxKIUKM2qUvKc3Vn1iVp-opzsMOU9mt4QkmJsvuGVM`**

⏬ representa

### Autenticação e Autorização

É o processo de verificar a identidade de um usuário. É provar que a pessoa é quem ela diz ser.

**Fluxo de autenticação** ➡️ Usuário faz login em uma aplicação, ele fornece as credenciais (e-mail e senha) que serão verificadas ➡️ se as credenciais forem válidas, o usuário será considerado autenticado 🔓

**Autorização**

Define o que um usuário autenticado pode ou não fazer dentro do sistema. Depois de identificado, o sistema verica quais permissões o usuário tem.

**Fluxo de autorização** ➡️ um usuário pode estar autenticado no sistema, mas ainda não ter permissão para acessar um painel administrativo ou excluir dados ⁉️ A autorização determina esse nível de acesso com base no papel (role) ou permissões atribuídas ao usuário.

**Resumo**

Autenticação: processo de identificação do usuário

Autorização: processo de verificar a permissão do usuário dentro do sistema

### JWT - entendo a fundo.

Pense nele como um passaporte digital, ele carrega suas informações (quem é você e o que pode fazer) e tem uma assinatura que garante sua autenticidade.

A grande vantagem dele é que ele é **`stateless`** (sem estado), ou seja, não é preciso guardar nenhuma informação no servidor, pois todas as informações já estão contidas nele. Simplifica muito e ajuda arquiteturas de microserviços ou quando você tem um frontend e backend desacoplados.

🦴 Anotamia de um JWT

**Header:** contém os metadados sobre o token. Geralmente, informa o tipo do token (`typ` que é JWT) e o algoritmo de assinatura usado (`alg`: `hs256` ou `rs256`)

```json
{
  "alg": "hs256",
  "typ": "JWT"
}
```

🔃 **Payload**

É aqui onde a mágica acontece, o payload contém os `claims` (declarações), que são as informações que serão transmitidas sobre o usuário ou outros dados relevantes. Existem `claims` já registradas por padrão como `sub` - o id do usuário, e `exp` - a data de expiração. e você pode adicionar as suas próprias

```json
{
  "sub": "user-123",
  "name": "Laís",
  "admin": false,
  "exp": 1644768000
}
```

<aside>
⚠️

O payload é apenas codificado (em Base64), não criptografado. Qualquer pessoa pode decodificá-lo. Portanto, **nunca** coloque informações sensíveis, como senhas, aqui dentro!

</aside>

✍️**Signature**

É a parte que garante a segurança. A assinatura é gerada combinando o `header`, o `payload` e uma chave secreta (que somente o servidor conhece), tudo isso é passado para o algoritmo de assinatura. Se alguem tentar alterar essas variáveis, a assinatura não irá mais funcionar e o token será invalidado.

**Fluxo de autenticação na prática: do Login à Validação**

- Login do usuário: o usuário irá enviar suas credenciais para a API
- Validação: O servidor verifica se as credenciais estão corretas no banco de dados
- Geração do Token: se tudo estiver correto, o servidor cria um JWT com as informações no `payload` e o assina com a chave secreta.
- Envio ao cliente: O servidor retorna o JWT para a aplicação cliente (navegador ou app mobile)
- Armazenamento: o cliente armazena essa informação de maneira segura
  - Requisições futuras: para cada requisição a uma rota protegida, o cliente envia o JWT no cabeçalho `Authorization`, geralmente no formato`Bearer <Token>`
- Verificação no servidor: a cada requisição, o servidor pega o token, verifica a assinatura para garantir que ele é autentico e não foi modificado. Se a assinatura e o token não tiver expirado, o acesso é liberado.

**Como não deixar brechas no JWT**

Onde guardar o token? `localStorage` vs `HttpOnly Cookies`

- `localStorage` : é a forma mais simples, o javascript do front-end pode acessar facilmente e enviar tokens facilmente. o problema é a vulnerabilidades e ataques Cross-site Scripting (XSS). Se um invasor injetar um script malicioso na sua página, ele pode roubar o token.
- `HttpOnly Cookies`: são cookies que não podem ser acessados via JavaScript. O navegador anexa automaticamente a cada requisição ao seu domínio. Isso mitiga o risco de roubo de token por XSS. **O problema:** requer proteção contra ataques de Cross-Site Request Forgery (CSRF)

<aside>
💡

Para a maioria das aplicações web, usar `HttpOnly cookies` é a abordagem mais segura, desde que você crie uma estratégia anti-CSRF (como tokens CSRF)

</aside>

**A importância do `refresh token`**

`acess token` devem ter vida curta (ex: 15 minutos) mas não podemos forçar um usuário a fazer login a cada 15 min.

A solução é usar `refresh token`. segue o fluxo:

1. No Login, o servidor gera dois tokens: um`acess token` (curto) e um `refresh token` (longo, ex: 7 dias)
2. O `acess token` é usado para as rotas protegidas
3. Quando o `acess token` expira, o cliente usa o `refresh token` para solicitar um novo `acess token` em um endpoint específico (ex: `/refresh_token`, sem precisar do usuário fazer login de novo.

### Vulnerabilidades comuns e como se defender

- **Algoritmo** `none`**:** alguns servidores aceitavam tokens com o algoritmo de assinatura definido como `"none"`. Um invasor poderia simplesmente remover a assinatura e acessar o sistema. **Mitigação:** Sua biblioteca de validação **deve** ter uma lista de algoritmos permitidos (ex: `['HS256', 'RS256']`).
- **Chaves Secretas Fracas:** se sua chave secreta for "123456", ela pode ser quebrada por força bruta. **Mitigação:** Use segredos longos, complexos e aleatórios, e guarde-os em variáveis de ambiente, nunca no código.
- **Vazamento de Informações no Payload:** lembre-se, o payload é visível. **Mitigação:** Nunca coloque dados sensíveis nele.

**Implementando Autenticação JWT (exemplo em javascript)**

é necessário instalar a biblioteca `jsonwebtoken`

```jsx
const jwt = require("jsonwebtoken");

// Suponha que você já validou o usuário e a senha
// user.id e user.name viriam do seu banco de dados

async function handleLogin(req, res) {
  const { email, password } = req.body;

  // Lógica para encontrar o usuário e validar a senha com bcrypt...
  const user = { id: "user-123", name: "Rodrigo" }; // Exemplo de usuário

  // Se as credenciais estiverem corretas:
  const payload = { userId: user.id, name: user.name };
  const secret = process.env.JWT_SECRET; // Guarde seu segredo em variáveis de ambiente!
  const options = { expiresIn: "900000ms" }; // Token expira em 15 minutos

  const token = jwt.sign(payload, secret, options);

  res.json({ accessToken: token });
}
```

**Protegendo as rotas com middlewares**

```jsx
// middleware/authenticateToken.js
const jwt = require("jsonwebtoken");

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Formato "Bearer TOKEN"

  if (token == null) {
    return res.sendStatus(401); // Se não há token, não autorizado
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403); // Se o token não for válido, acesso proibido
    }

    // O payload decodificado é adicionado ao objeto da requisição
    req.user = user;
    next(); // Passa para a próxima função (o controller da rota)
  });
}

// Em seu arquivo de rotas:
// app.get('/perfil', authenticateToken, (req, res) => { ... });
```

[Autenticação JWT: como proteger suas APIs de forma moderna](https://www.rocketseat.com.br/blog/artigos/post/autenticacao-jwt-guia-proteger-api-nodejs)

**Comandos usados**

`sign()`

`verify()`
