Documentação de Segurança - SecureRNKit-Expo
Introdução
Este documento detalha as decisões de segurança e as implementações práticas realizadas no SecureRNKit-Expo, um boilerplate para o desenvolvimento de aplicações React Native (utilizando Expo) com um foco robusto em segurança. O objetivo principal é fornecer um ponto de partida seguro e confiável, mitigando vulnerabilidades comuns em aplicações móveis e promovendo as melhores práticas de segurança desde as fases iniciais do desenvolvimento.

A segurança em aplicações móveis é um processo contínuo que envolve múltiplas camadas. Este boilerplate aborda aspectos críticos, desde o armazenamento de dados sensíveis e a comunicação de rede até a validação de entradas e a proteção contra ataques conhecidos.

1. Autenticação JWT Segura
   A autenticação é um dos pilares de segurança de qualquer aplicação. A forma como tokens são armazenados, transmitidos e gerenciados é crucial para prevenir acessos não autorizados.

1.1. Armazenamento Seguro de Tokens (expo-secure-store)
Decisão de Segurança:
Tokens de autenticação, como o Access Token (JWT) e o Refresh Token, são dados altamente sensíveis. Armazená-los em locais inseguros, como AsyncStorage (que não é criptografado e é facilmente acessível em dispositivos comprometidos) ou variáveis globais em JavaScript (que podem ser inspecionadas), representa um risco significativo. Um vazamento desses tokens pode resultar em acesso não autorizado à conta do usuário.

Implementação:
Utilizamos a biblioteca expo-secure-store para o armazenamento de tokens. Esta biblioteca aproveita os mecanismos de armazenamento de credenciais nativos e seguros do sistema operacional:

Android: Utiliza o Android Keystore System.

iOS: Utiliza o iOS Keychain.

Esses sistemas fornecem um armazenamento criptografado e isolado, protegido contra acesso não autorizado por outras aplicações ou por usuários com acesso root/jailbreak (embora nenhuma proteção seja 100% infalível contra malware avançado ou ataques físicos ao dispositivo).

Caminho do Arquivo: src/services/secureStorage.ts

Exemplo de Código (Trecho de src/services/secureStorage.ts):

// ... imports
export const SecureStorageService = {
saveToken: async (token: string): Promise<void> => {
try {
await SecureStore.setItemAsync('user_jwt', token);
console.log('JWT salvo com sucesso no SecureStore.');
} catch (error) {
console.error('Erro ao salvar JWT no SecureStore:', error);
throw error;
}
},
getToken: async (): Promise<string | null> => {
try {
const token = await SecureStore.getItemAsync('user_jwt');
return token;
} catch (error) {
console.error('Erro ao obter JWT do SecureStore:', error);
return null;
}
},
// ... métodos para Refresh Token e delete
};

1.2. Cliente HTTP com Interceptores (axios)
Decisão de Segurança:
É essencial que todas as requisições à API que exigem autenticação incluam o JWT de forma padronizada e segura. Além disso, a aplicação deve ser capaz de detectar quando um token está expirado (401 Unauthorized) e iniciar um processo de renovação (refresh token) ou desautenticação do usuário.

Implementação:
Configuramos uma instância do Axios (src/services/api.ts) com interceptores de requisição e resposta:

Interceptor de Requisição: Automaticamente obtém o Access Token do SecureStorageService e o anexa ao cabeçalho Authorization de cada requisição no formato Bearer <token>. Este é o padrão da indústria para envio de tokens de autenticação.

Interceptor de Resposta (Tratamento de 401 Unauthorized):

Detecta respostas com status 401 Unauthorized, que geralmente indicam um Access Token expirado ou inválido.

Implementa um fluxo de refresh token: se não estiver em um processo de refresh (controlado pela flag isRefreshing), ele enfileira a requisição original e tenta usar o Refresh Token (também armazenado de forma segura) para obter um novo Access Token do backend.

Se o refresh for bem-sucedido, os novos tokens são salvos, e a requisição original que falhou é re-tentada com o novo token.

Se o refresh falhar (ex: refresh token inválido ou expirado), a sessão é considerada inválida, e o usuário é deslogado (tokens limpos e redirecionado para a tela de login).

Um mecanismo de fila (failedQueue) e uma flag (isRefreshing) são utilizados para evitar múltiplos refreshes simultâneos e garantir que todas as requisições pendentes sejam processadas de forma ordenada.

Caminho do Arquivo: src/services/api.ts

Exemplo de Código (Trecho de src/services/api.ts):

// ... imports
const api = axios.create({ /_ ... _/ });

api.interceptors.request.use(async (config) => {
const token = await SecureStorageService.getToken();
if (token) {
config.headers.Authorization = `Bearer ${token}`;
}
return config;
});

api.interceptors.response.use(
(response) => response,
async (error) => {
const originalRequest = error.config;
if (error.response?.status === 401 && !originalRequest.\_retry && !isRefreshing) {
originalRequest.\_retry = true;
isRefreshing = true;
// ... lógica de refresh token e re-tentativa da requisição
}
return Promise.reject(error);
}
);
// ...

1.3. Módulo de Autenticação (AuthService)
Decisão de Segurança:
Centralizar a lógica de negócio relacionada à autenticação em um único módulo (AuthService) é crucial para garantir consistência, segurança e facilitar a manutenção. Isso evita a duplicação de código e pontos de falha.

Implementação:
Um serviço AuthService (src/services/auth.ts) encapsula as interações com o api.ts (para fazer as chamadas de login/logout/refresh) e o secureStorage.ts (para salvar/obter/deletar tokens). Ele fornece métodos claros para:

login(email, password): Envia credenciais para o backend, valida os dados (com Zod) e salva os tokens retornados de forma segura.

logout(): Limpa todos os tokens armazenados, efetivamente encerrando a sessão do usuário.

refreshToken(): (Chamado internamente pelo interceptor do Axios) Lida com a lógica de enviar o refresh token para o backend e atualizar os access/refresh tokens.

isAuthenticated(): Verifica a presença de um token para indicar o estado de login do usuário.

Caminho do Arquivo: src/services/auth.ts

2. Sanitização e Validação de Entradas
   A manipulação de dados de entrada é um vetor comum para ataques de injeção. A validação rigorosa e a sanitização são essenciais para proteger a aplicação.

2.1. Sanitização de Entradas (src/utils/sanitization.ts)
Decisão de Segurança:
Dados recebidos de usuários (via formulários) ou de APIs (especialmente strings que serão renderizadas na interface do usuário) podem conter scripts maliciosos ou tags HTML indesejadas. Exibir esse conteúdo diretamente pode levar a ataques de Cross-Site Scripting (XSS).

Implementação:
Criamos um conjunto de funções utilitárias em src/utils/sanitization.ts para mitigar XSS:

escapeHtml(text): A principal defesa contra XSS ao exibir dados. Substitui caracteres HTML especiais (<, >, &, ", ') por suas entidades HTML correspondentes. Isso garante que o texto seja renderizado literalmente e não como código HTML, neutralizando scripts maliciosos.

stripHtmlTags(htmlString): Remove todas as tags HTML de uma string. Útil quando apenas texto puro é esperado e qualquer formatação HTML é indesejada.

Validação de Formato: Funções como isValidEmail(email) e isAlphanumericWithSpaces(text) são fornecidas para validar se os dados estão no formato esperado. Embora não removam código malicioso, a validação rigorosa de entradas é uma camada crítica de segurança que reduz a superfície de ataque para injeções e garante a integridade dos dados.

Caminho do Arquivo: src/utils/sanitization.ts

Exemplo de Código (Trecho de src/utils/sanitization.ts):

// ... imports
export const escapeHtml = (text: string): string => {
return text
.replace(/&/g, '&amp;')
.replace(/</g, '&lt;')
.replace(/>/g, '&gt;')
.replace(/"/g, '&quot;')
.replace(/'/g, '&#039;');
};

export const stripHtmlTags = (htmlString: string): string => {
return htmlString.replace(/<[^>]\*>?/gm, '');
};

export const isValidEmail = (email: string): boolean => {
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
return emailRegex.test(email);
};
// ...

2.2. Validação de Esquemas de Dados (Zod)
Decisão de Segurança:
Para garantir a integridade dos dados e prevenir ataques baseados em dados malformados ou inesperados, é crucial validar a estrutura e os tipos de dados tanto nas entradas da aplicação quanto nas respostas recebidas de APIs. Isso previne bugs, manipulações de dados e potenciais explorações.

Implementação:
Utilizamos a biblioteca Zod para definir e validar esquemas de dados.

Definição de Esquemas: Em src/utils/validationSchemas.ts, definimos z.object (e outros tipos Zod) para descrever a forma esperada de objetos (ex: userSchema, loginSchema). Isso permite definir campos obrigatórios, tipos, validações de formato (email, UUID) e valores permitidos (enums).

Validação em Tempo de Execução: A função utilitária validateData (src/utils/validationSchemas.ts) utiliza schema.parse(data) para validar dados em tempo de execução. Se os dados não corresponderem ao esquema, um erro detalhado é lançado, impedindo o processamento de dados inválidos ou maliciosos.

Tipagem Forte: Zod pode inferir tipos TypeScript a partir dos esquemas (z.infer<typeof schema>), garantindo que os dados após a validação sejam tipados corretamente em todo o aplicativo, melhorando a segurança e a manutenibilidade do código.

Caminho do Arquivo: src/utils/validationSchemas.ts

Exemplo de Código (Trecho de src/utils/validationSchemas.ts e uso em src/services/auth.ts):

// src/utils/validationSchemas.ts
import { z } from 'zod';

export const userSchema = z.object({
id: z.string().uuid("ID do usuário deve ser um UUID válido."),
name: z.string().min(2, "Nome deve ter no mínimo 2 caracteres."),
email: z.string().email("Formato de email inválido."),
// ...
});

export const loginSchema = z.object({
email: z.string().email("Formato de email inválido."),
password: z.string().min(6, "Senha deve ter no mínimo 6 caracteres."),
});

export const validateData = <T>(schema: z.ZodSchema<T>, data: unknown): T => {
try {
return schema.parse(data);
} catch (error: any) {
// ... tratamento de erro
}
};

// Uso em src/services/auth.ts
import { loginSchema, userSchema, validateData } from '../utils/validationSchemas';

// No login:
const credentials = validateData(loginSchema, { email, password }); // Valida entrada
const user = validateData(userSchema, userData); // Valida dados do backend

3. Segurança de Comunicação de Rede
   A comunicação segura com o backend é fundamental para proteger a confidencialidade e a integridade dos dados em trânsito.

3.1. HTTPS Only
Decisão de Segurança:
Todas as comunicações de rede da aplicação devem ocorrer exclusivamente via HTTPS. Isso garante que os dados sejam criptografados enquanto viajam pela rede, protegendo-os contra eavesdropping (escuta não autorizada) e ataques Man-in-the-Middle (MITM).

Implementação:

Configuração do Cliente HTTP (Axios): A baseURL do nosso cliente Axios (src/services/api.ts) é definida com https://, garantindo que todas as requisições iniciadas por ele usem este protocolo.

iOS: App Transport Security (ATS): O iOS, a partir da versão 9, força o App Transport Security (ATS) por padrão. Isso significa que, por padrão, todas as conexões de rede devem usar HTTPS que atendam a padrões de segurança específicos da Apple. Não é necessário código adicional, e é crucial evitar adicionar exceções em Info.plist que desabilitem o ATS (NSAllowsArbitraryLoads = true), a menos que haja um motivo de compatibilidade legado extremamente forte e compreendido.

Android: Network Security Configuration: Para o Android (a partir do Android 7.0 / API 24), utilizamos um arquivo XML (android/app/src/main/res/xml/network_security_config.xml) para aplicar políticas de segurança de rede:

A propriedade cleartextTrafficPermitted="false" desabilita explicitamente o tráfego HTTP não criptografado para os domínios configurados e para a configuração base.

O arquivo network_security_config.xml é referenciado no AndroidManifest.xml (android:networkSecurityConfig="@xml/network_security_config"), garantindo que as políticas sejam aplicadas.

Caminhos dos Arquivos:

src/services/api.ts

ios/SecureRNKitExpo/Info.plist (para verificação, não modificação padrão)

android/app/src/main/res/xml/network_security_config.xml

android/app/src/main/AndroidManifest.xml

3.2. SSL/TLS Pinning
Decisão de Segurança:
Para um nível de segurança ainda maior contra ataques MITM, o SSL/TLS Pinning é implementado. Ele garante que a aplicação se comunique apenas com servidores cujos certificados (ou chaves públicas) foram previamente "fixados" (confiáveis) no código do aplicativo. Isso impede que um invasor intercepte a comunicação, mesmo que ele obtenha um certificado válido de uma Autoridade Certificadora (CA) confiável.

Aviso Importante: O Pinning requer manutenção ativa. Se o certificado do servidor ou a chave pública mudar (ex: renovação de certificado), o aplicativo precisará ser atualizado com as novas chaves, ou a comunicação será bloqueada. Isso deve ser considerado no pipeline de CI/CD e no plano de manutenção.

Implementação:
Utilizamos a biblioteca react-native-ssl-public-key-pinning para integrar a funcionalidade de pinning.

O hostname da API (API_HOSTNAME) é extraído da API_BASE_URL para garantir que o pinning se aplique apenas ao domínio correto.

Os hashes SHA256 Base64 das chaves públicas permitidas são configurados no array ALLOWED_PUBLIC_KEYS em src/services/api.ts. É crucial que estas chaves sejam obtidas de forma segura e correspondam às chaves do seu servidor de API.

Caminho do Arquivo: src/services/api.ts

Exemplo de Código (Trecho de src/services/api.ts):

// ... imports
import { SslPinning } from 'react-native-ssl-public-key-pinning';

const API_HOSTNAME = new URL(API_BASE_URL).hostname;

// TODO: SUBSTITUA PELOS HASHES SHA256 BASE64 DAS CHAVES PÚBLICAS DO SEU SERVIDOR
const ALLOWED_PUBLIC_KEYS = [
'YOUR_SERVER_PUBLIC_KEY_SHA256_BASE64_HERE_1',
// ...
];

SslPinning.set = {
host: API_HOSTNAME,
publicKeyHashes: ALLOWED_PUBLIC_KEYS,
// ... outras configurações
};
// ...

4. Segurança do Dispositivo e Ambiente
   A segurança não se limita à comunicação com o backend. O ambiente em que a aplicação é executada também pode apresentar riscos.

4.1. Detecção de Root/Jailbreak
Decisão de Segurança:
Dispositivos rooted (Android) ou jailbroken (iOS) têm o sistema operacional comprometido, o que expõe o aplicativo a um risco maior. Nesses dispositivos, malware pode ter acesso privilegiado ao sistema de arquivos, memória e processos de outras aplicações, tornando as medidas de segurança normais menos eficazes.

Implementação:
Utilizamos a biblioteca react-native-device-info para verificar o status de root/jailbreak do dispositivo.

O método DeviceInfo.isRooted() retorna true se o dispositivo for detectado como comprometido.

A função isEmulator() também é usada para identificar se o aplicativo está sendo executado em um ambiente de emulação/simulação, que geralmente é menos seguro para testes de produção.

Uma verificação de **DEV** é usada para alertar sobre o modo de depuração em builds de produção (onde deveria estar desativado).

Ao detectar um dispositivo comprometido (ex: em app/\_layout.tsx), a aplicação pode tomar ações preventivas, como alertar o usuário, desabilitar funcionalidades sensíveis ou até mesmo sair da aplicação, dependendo da política de segurança.

Caminho do Arquivo: src/services/deviceSecurity.ts e app/\_layout.tsx (para uso)

Exemplo de Código (Trecho de src/services/deviceSecurity.ts e app/\_layout.tsx):

// src/services/deviceSecurity.ts
import DeviceInfo from "react-native-device-info";

export const DeviceSecurityService = {
isDeviceCompromised: async (): Promise<boolean> => {
try {
const isRooted = await DeviceInfo.isRooted();
if (isRooted) {
console.warn("Alerta de Segurança: Dispositivo está ROOTED/JAILBROKEN!");
}
return isRooted;
} catch (error) { /_ ... _/ }
},
isEmulator: async (): Promise<boolean> => { /_ ... _/ },
isDebugMode: (): boolean => { /_ ... _/ },
};

// app/\_layout.tsx
import { useEffect } from 'react';
import { Alert } from 'react-native';
import { DeviceSecurityService } from '../src/services/deviceSecurity';

export default function RootLayout() {
useEffect(() => {
const checkSecurity = async () => {
const isCompromised = await DeviceSecurityService.isDeviceCompromised();
if (isCompromised) {
Alert.alert(
'Alerta de Segurança',
'Este dispositivo parece estar comprometido (rooted/jailbroken). Algumas funcionalidades podem ser desativadas por segurança.'
);
}
};
checkSecurity();
}, []);
// ...
}

4.2. Gerenciamento Seguro de Variáveis de Ambiente
Decisão de Segurança:
NUNCA deve-se armazenar chaves de API, URLs de backend sensíveis, credenciais de terceiros ou quaisquer outros segredos diretamente no código-fonte da aplicação ou em arquivos que são comitados ao controle de versão (Git). Isso expõe essas informações a qualquer pessoa com acesso ao repositório.

Implementação:
Utilizamos a biblioteca react-native-dotenv para gerenciar variáveis de ambiente:

As variáveis são definidas em um arquivo .env na raiz do projeto.

O arquivo .env é explicitamente adicionado ao .gitignore para garantir que nunca seja versionado.

O babel.config.js é configurado para carregar essas variáveis e disponibilizá-las no código através de um módulo virtual (@env), permitindo o acesso seguro em tempo de execução.

Para que o TypeScript reconheça essas variáveis, um arquivo de declaração de tipos (declaration.d.ts) é criado.

Caminhos dos Arquivos:

.env (na raiz do projeto, não versionado)

.gitignore

babel.config.js

declaration.d.ts

Exemplo de Código (Trecho de babel.config.js e .env):

// babel.config.js
module.exports = function(api) {
// ...
plugins: [
['module:react-native-dotenv', { /* ...config */ }],
// ...
];
};

// .env
API_BASE_URL=https://api.seubackend.com/v1
JWT_SECRET_KEY=sua_chave_secreta_jwt_para_testes

4.3. Conceito de Backend for Frontend (BFF)
Decisão de Segurança:
Para secrets extremamente sensíveis (ex: chaves de API de serviços de pagamento, credenciais de bases de dados ou outros secrets que nunca devem tocar o dispositivo do cliente), a melhor prática é utilizar um Backend for Frontend (BFF).

Implementação (Conceitual/Arquitetural):
Um BFF é uma camada de backend leve que atua como um intermediário entre o aplicativo móvel e as APIs de terceiros ou serviços internos sensíveis.

O aplicativo móvel se comunica apenas com o BFF.

O BFF (que roda em um ambiente de servidor seguro e controlado) é responsável por armazenar e usar as chaves sensíveis para fazer as chamadas reais aos serviços de terceiros.

Isso garante que as chaves sensíveis nunca sejam expostas no código do aplicativo móvel, mesmo após engenharia reversa.

5. Melhores Práticas Contínuas
   A segurança é um alvo em movimento. Manter a aplicação segura requer vigilância e processos contínuos.

5.1. Atualizações de Dependências
Decisão de Segurança:
Manter todas as bibliotecas e dependências da aplicação atualizadas é vital. Vulnerabilidades de segurança (CVEs - Common Vulnerabilities and Exposures) são frequentemente descobertas em versões mais antigas de softwares e bibliotecas. Os desenvolvedores das bibliotecas lançam patches e correções em novas versões. Usar dependências desatualizadas aumenta o risco de explorações conhecidas.

Processo Recomendado:

Rotina de Verificação: Estabeleça um cronograma regular (ex: mensal ou trimestral) para verificar e atualizar as dependências.

Ferramentas:

npm outdated ou yarn outdated: Lista dependências desatualizadas.

npm update ou yarn upgrade: Atualiza as dependências para as últimas versões compatíveis com o package.json.

npm-check-updates (ncu): Permite atualizar dependências para as últimas versões disponíveis, ignorando restrições do package.json (usar com cautela, pois pode introduzir breaking changes).

Testes Automatizados: Mantenha uma suíte de testes (unitários, de integração, e-to-e) robusta. Isso é essencial para garantir que as atualizações de dependências não introduzam regressões ou bugs inesperados.

Monitoramento de Vulnerabilidades: Considere integrar ferramentas de varredura de vulnerabilidades (ex: Snyk, Dependabot) ao seu pipeline de CI/CD para alertas proativos sobre dependências com vulnerabilidades conhecidas.

5.2. Testes de Segurança
Decisão de Segurança:
Mesmo com as melhores práticas de desenvolvimento seguro, falhas podem ocorrer. Testes de segurança proativos são cruciais para identificar vulnerabilidades antes que possam ser exploradas por atacantes.

Práticas Recomendadas:

Testes de Penetração (Penetration Testing): Contratar ou realizar testes de penetração regulares para simular ataques e identificar vulnerabilidades exploráveis.

Análise Estática de Código (SAST - Static Application Security Testing): Integrar ferramentas de SAST no pipeline de CI/CD para analisar o código-fonte sem executá-lo, identificando padrões de código vulneráveis.

Análise Dinâmica de Código (DAST - Dynamic Application Security Testing): Utilizar ferramentas DAST para testar a aplicação em execução, identificando vulnerabilidades que podem ser ativadas em tempo de execução.

Varredura de Vulnerabilidades em Dependências: Usar ferramentas que varrem o node_modules em busca de vulnerabilidades conhecidas em bibliotecas de terceiros.

5.3. Conscientização do Desenvolvedor
Decisão de Segurança:
O elemento humano é frequentemente o elo mais fraco na cadeia de segurança. Desenvolvedores bem informados e treinados em segurança são a primeira linha de defesa contra vulnerabilidades.

Práticas Recomendadas:

Treinamento em Segurança: Oferecer treinamento regular sobre OWASP Top 10 Mobile, princípios de desenvolvimento seguro e as ameaças mais recentes em aplicações móveis.

Revisão de Código (Code Review): Implementar um processo rigoroso de revisão de código com foco em segurança, onde colegas revisam o código uns dos outros em busca de vulnerabilidades.

Cultura de Segurança: Fomentar uma cultura onde a segurança é uma preocupação compartilhada e prioritária em todas as fases do ciclo de vida do desenvolvimento de software.
