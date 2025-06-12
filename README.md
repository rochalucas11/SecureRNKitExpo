SecureRNKit-Expo
📄 Visão Geral do Projeto
O SecureRNKit-Expo é um boilerplate (template base) para o desenvolvimento de aplicações React Native utilizando Expo, com um foco primordial em segurança. Ele foi projetado para fornecer uma base sólida e robusta, incorporando as melhores práticas de segurança desde o início do desenvolvimento.

O objetivo é minimizar vulnerabilidades comuns em aplicações móveis, como XSS, problemas de armazenamento de tokens e comunicação de rede insegura, permitindo que as equipes de desenvolvimento construam com confiança.

✨ Funcionalidades de Segurança Implementadas
Este boilerplate inclui as seguintes medidas de segurança:

Autenticação JWT Segura:

Armazenamento de Tokens: Utiliza expo-secure-store para armazenar o Access Token (JWT) e o Refresh Token de forma segura, aproveitando os mecanismos de armazenamento de credenciais nativos do dispositivo (Android Keystore e iOS Keychain).

Fluxo de Refresh Token: Implementa um interceptor no Axios para lidar automaticamente com tokens de acesso expirados, utilizando o Refresh Token para obter um novo Access Token sem a necessidade de o usuário refazer o login.

Cliente HTTP Configurado (Axios):

HTTPS Obrigatório: Todas as comunicações de rede são forçadas a usar HTTPS, garantindo criptografia em trânsito.

Interceptores de Requisição e Resposta: Gerenciam a inclusão automática do JWT nas requisições e tratam respostas de erro (ex: 401 Unauthorized).

Sanitização de Entradas:

Funções utilitárias para escapeHtml (escapar caracteres HTML) e stripHtmlTags (remover tags HTML), prevenindo ataques de Cross-Site Scripting (XSS) ao exibir dados do usuário ou de APIs.

Funções básicas de validação como isValidEmail para garantir o formato correto das entradas.

Validação de Esquemas de Dados (Zod):

Utiliza a biblioteca Zod para definir e validar esquemas de dados, garantindo que as entradas da aplicação e as respostas das APIs estejam no formato esperado e correspondam aos tipos definidos. Isso previne erros de dados e potenciais manipulações.

Detecção de Root/Jailbreak:

Usa react-native-device-info para verificar se o dispositivo está rooted (Android) ou jailbroken (iOS), permitindo que a aplicação tome ações preventivas (ex: alertar o usuário, desabilitar funcionalidades sensíveis).

Gerenciamento Seguro de Variáveis de Ambiente:

Utiliza react-native-dotenv para carregar variáveis de ambiente (como URLs de API), garantindo que secrets não sejam comitados no controle de versão (o arquivo .env é incluído no .gitignore).

Documentação Detalhada de Segurança:

Um arquivo docs/SECURITY.md explica cada decisão de segurança, o "porquê" por trás das implementações e as melhores práticas.

🛠️ Tecnologias Utilizadas
React Native

Expo (Managed Workflow)

TypeScript

Axios (para requisições HTTP)

expo-secure-store (para armazenamento seguro)

react-native-device-info (para informações e segurança do dispositivo)

react-native-dotenv (para variáveis de ambiente)

Zod (para validação de esquemas de dados)

Expo Router (para navegação baseada em arquivos)

🚀 Configuração e Primeiros Passos
Siga os passos abaixo para configurar e rodar o projeto localmente.

Pré-requisitos
Node.js (LTS recomendado)

npm ou Yarn

Expo Go app (instalado no seu dispositivo móvel ou emulador)

Instalação
Clone o Repositório:

git clone https://github.com/rochalucas11/SecureRNKitExpo.git
cd SecureRNKitExpo

Instale as Dependências:

npm install

# ou

yarn install

Configuração do Ambiente (.env):
Crie um arquivo .env na raiz do projeto (ele já deve estar no .gitignore):

API_BASE_URL=https://api.seubackend.com/v1 # Substitua pela URL da sua API
JWT_SECRET_KEY=sua_chave_secreta_jwt_para_testes # Exemplo

Importante: Nunca comite seu arquivo .env para o controle de versão!

Obtenha o hash SHA256 Base64 da chave pública do certificado do seu servidor (substitua api.seubackend.com pelo seu domínio real):

echo | openssl s_client -servername api.seubackend.com -connect api.seubackend.com:443 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64

Abra src/services/api.ts e substitua os placeholders em ALLOWED_PUBLIC_KEYS com o hash obtido.

Configuração de Segurança de Rede (Android):

Abra android/app/src/main/res/xml/network_security_config.xml.

Substitua api.seubackend.com e quaisquer outros domínios pela URL real da sua API e de outros serviços HTTPS.

▶️ Como Rodar a Aplicação
Para iniciar o servidor de desenvolvimento do Expo:

npx expo start

Após executar o comando, o Metro Bundler abrirá no seu navegador. Você pode:

Escanear o QR Code: Use o aplicativo Expo Go no seu celular (Android ou iOS) para escanear o QR code exibido no terminal ou no navegador.

Rodar em Emulador/Simulador: Pressione a para Android ou i para iOS no terminal onde npx expo start está rodando.

📂 Estrutura do Projeto
A estrutura do projeto é organizada para clareza e manutenção, separando as preocupações de segurança, serviços e componentes da UI.

SecureRNKit-Expo/
├── app/ # Rotas do Expo Router (navegação baseada em arquivos)
│ ├── (tabs)/ # Agrupamento de rotas com abas (ex: Home, Explore)
│ │ ├── \_layout.tsx
│ │ ├── index.tsx # Tela de exemplo principal
│ │ └── explore.tsx # Tela de exemplo
│ ├── \_layout.tsx # Layout principal da aplicação e Stack Navigator
│ └── modal.tsx # Exemplo de modal
├── src/
│ ├── components/ # Componentes React reutilizáveis
│ ├── services/ # Módulos de serviço (API, autenticação, armazenamento seguro, segurança do dispositivo)
│ │ ├── api.ts # Cliente Axios
│ │ ├── auth.ts # Lógica de autenticação (login, logout, refresh token)
│ │ ├── secureStorage.ts# Armazenamento seguro de tokens (expo-secure-store)
│ │ └── deviceSecurity.ts# Detecção de root/jailbreak e outras verificações de dispositivo
│ ├── utils/ # Funções utilitárias (sanitização, validação de esquemas)
│ │ ├── sanitization.ts # Funções para escapar HTML e remover tags
│ │ └── validationSchemas.ts # Esquemas de validação de dados (Zod)
│ ├── hooks/ # Custom Hooks React
│ ├── contexts/ # Context API (ou store para Redux/Zustand, se utilizado)
│ └── assets/ # Imagens, fontes, etc.
├── docs/ # Documentação do projeto
│ └── SECURITY.md # **Documento detalhado sobre as decisões de segurança**
├── .env # Variáveis de ambiente (não versionado)
├── babel.config.js # Configuração do Babel (incluindo react-native-dotenv)
├── package.json # Dependências e scripts do projeto
├── tsconfig.json # Configuração do TypeScript
└── ... outros arquivos de configuração Expo/React Native

🔒 Documentação de Segurança Aprofundada
Para uma compreensão completa de cada decisão e implementação de segurança, consulte o arquivo docs/SECURITY.md na raiz deste repositório. Ele explica em detalhes o "porquê" e o "como" de cada medida.

🗺️ Roadmap e Melhorias Futuras
Este boilerplate fornece uma base sólida, mas a segurança é um processo contínuo. Melhorias futuras podem incluir:

Integração de Testes de Segurança: Adicionar testes de unidade e integração específicos para as funcionalidades de segurança.

Análise Estática de Código (SAST): Configurar ferramentas de análise estática para identificar potenciais vulnerabilidades no código-fonte.

Gerenciamento de Segredos em Tempo de Execução: Explorar soluções mais avançadas para gerenciar chaves de API e outros secrets em tempo de execução (ex: Backend for Frontend - BFF).

Políticas de Cache Seguras: Implementar cabeçalhos de cache seguros para recursos da aplicação.

Atualizações de Dependências: Manter todas as dependências atualizadas regularmente para mitigar vulnerabilidades conhecidas.

🤝 Contribuição
Contribuições são bem-vindas! Se você tiver sugestões, melhorias ou encontrar bugs, sinta-se à vontade para abrir uma issue ou enviar um pull request.\*\*\*\*
