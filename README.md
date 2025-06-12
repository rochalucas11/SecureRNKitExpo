# Secure Frontend Boilerplate (React Native Expo) - `SecureRNKit-Expo`

## Introdução

Este documento detalha as decisões e implementações de segurança no `SecureRNKit-Expo`, um boilerplate para aplicações React Native (Expo) focado em prover uma base segura para o desenvolvimento. O objetivo é mitigar vulnerabilidades comuns e promover as melhores práticas de segurança desde o início do projeto.

## 1. Gerenciamento de Tokens de Autenticação (JWT)

A autenticação é um ponto crítico de qualquer aplicação. Utilizamos JWTs (JSON Web Tokens) para autenticação e autorização, seguindo um fluxo seguro com _refresh tokens_.

### 1.1. Armazenamento Seguro de Tokens (`expo-secure-store`)

**Decisão de Segurança:**
Tokens de autenticação (Access Token e Refresh Token) são dados sensíveis e não devem ser armazenados em locais de fácil acesso, como `AsyncStorage` ou variáveis globais em JavaScript. `AsyncStorage` não é criptografado e pode ser acessado por _malware_ ou por usuários com acesso _root_/_jailbreak_ ao dispositivo.

**Implementação:**
Utilizamos `expo-secure-store` para armazenar o JWT (Access Token) e o Refresh Token. Esta biblioteca utiliza os mecanismos de armazenamento de credenciais nativos do sistema operacional:

- **Android:** Android Keystore System
- **iOS:** iOS Keychain

Esses mecanismos fornecem um armazenamento criptografado e seguro, isolado de outras aplicações.

**Caminho do Arquivo:** `src/services/secureStorage.ts`

**Exemplo de Uso:**

```typescript
import { SecureStorageService } from "./src/services/secureStorage";

// Para salvar:
await SecureStorageService.saveToken("seu_jwt_aqui");
// Para obter:
const token = await SecureStorageService.getToken();
// Para deletar:
await SecureStorageService.deleteToken();
```
