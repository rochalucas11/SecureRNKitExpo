// src/services/auth.ts
import api from "./api"; // Nosso cliente Axios configurado
import { SecureStorageService } from "./secureStorage";
// import { router } from 'expo-router'; // Para redirecionar após login/logout

interface AuthTokens {
  accessToken: string;
  refreshToken?: string; // Opcional, dependendo da sua estratégia de backend
}

interface User {
  id: string;
  email: string;
  name?: string;
  // ... outras informações do usuário que o backend retornar
}

export const AuthService = {
  /**
   * Realiza o login do usuário e salva os tokens.
   * @param email O email do usuário.
   * @param password A senha do usuário.
   * @returns As informações do usuário logado.
   */
  login: async (email: string, password: string): Promise<User> => {
    try {
      // Endpoint de login no seu backend
      const response = await api.post<AuthTokens & { user: User }>(
        "/auth/login",
        { email, password }
      );

      const { accessToken, refreshToken, user } = response.data;

      await SecureStorageService.saveToken(accessToken);
      if (refreshToken) {
        await SecureStorageService.saveRefreshToken(refreshToken);
      }

      console.log("Login bem-sucedido!");
      // router.replace('/(tabs)'); // Redireciona para a tela principal
      return user;
    } catch (error) {
      console.error("Erro no login:", error);
      // Aqui você pode tratar erros específicos (ex: credenciais inválidas)
      throw error; // Propaga o erro para quem chamou a função
    }
  },

  /**
   * Realiza o logout do usuário, limpando os tokens.
   */
  logout: async (): Promise<void> => {
    try {
      await SecureStorageService.deleteToken();
      await SecureStorageService.deleteRefreshToken();
      console.log("Logout bem-sucedido!");
      // router.replace('/login'); // Redireciona para a tela de login
    } catch (error) {
      console.error("Erro ao fazer logout:", error);
      throw error;
    }
  },

  /**
   * Tenta refrescar o token de acesso usando o refresh token.
   * Este método é chamado pelo interceptor do Axios.
   * @returns O novo token de acesso.
   */
  refreshToken: async (): Promise<string> => {
    try {
      const currentRefreshToken = await SecureStorageService.getRefreshToken();
      if (!currentRefreshToken) {
        throw new Error("No refresh token available to refresh.");
      }

      // Endpoint para refrescar o token no seu backend
      const response = await api.post<AuthTokens>("/auth/refresh-token", {
        refreshToken: currentRefreshToken,
      });

      const { accessToken, refreshToken: newRefreshToken } = response.data;

      await SecureStorageService.saveToken(accessToken);
      if (newRefreshToken) {
        // O backend pode ou não retornar um novo refresh token
        await SecureStorageService.saveRefreshToken(newRefreshToken);
      }

      console.log("Token de acesso refrescado com sucesso!");
      return accessToken;
    } catch (error) {
      console.error("Erro ao refrescar token:", error);
      // Em caso de falha no refresh, o usuário deve ser deslogado
      await AuthService.logout(); // Limpa os tokens e força o logout
      throw error;
    }
  },

  /**
   * Verifica se o usuário está autenticado (tem um token válido).
   * @returns True se autenticado, false caso contrário.
   */
  isAuthenticated: async (): Promise<boolean> => {
    const token = await SecureStorageService.getToken();
    // Você pode adicionar lógica para validar o token aqui (ex: decodificar e checar expiração localmente)
    // No entanto, a validação principal deve ser feita no backend.
    return !!token;
  },
};
