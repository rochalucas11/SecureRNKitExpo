// src/services/auth.ts (ATUALIZADO com Zod)
import api from "./api";
import { SecureStorageService } from "./secureStorage";
import {
  loginSchema,
  userSchema,
  LoginCredentials,
  User,
  validateData,
} from "../utils/validationSchemas"; // Importe os esquemas Zod
// import { router } from 'expo-router';

interface AuthTokens {
  accessToken: string;
  refreshToken?: string;
}

export const AuthService = {
  login: async (email: string, password: string): Promise<User> => {
    try {
      const credentials = validateData(loginSchema, { email, password }); // Valida as credenciais de entrada

      const response = await api.post<AuthTokens & { user: unknown }>(
        "/auth/login",
        credentials
      );

      const { accessToken, refreshToken, user: userData } = response.data;

      // Valida os dados do usuário recebidos do backend
      const user = validateData(userSchema, userData);

      await SecureStorageService.saveToken(accessToken);
      if (refreshToken) {
        await SecureStorageService.saveRefreshToken(refreshToken);
      }

      console.log("Login bem-sucedido!");
      // router.replace('/(tabs)');
      return user;
    } catch (error) {
      console.error("Erro no login:", error);
      throw error;
    }
  },

  logout: async (): Promise<void> => {
    try {
      await SecureStorageService.deleteToken();
      await SecureStorageService.deleteRefreshToken();
      console.log("Logout bem-sucedido!");
      // router.replace('/login');
    } catch (error) {
      console.error("Erro ao fazer logout:", error);
      throw error;
    }
  },

  refreshToken: async (): Promise<string> => {
    // ... (restante da função é a mesma, pois a entrada é apenas o token, que já é uma string)
    try {
      const currentRefreshToken = await SecureStorageService.getRefreshToken();
      if (!currentRefreshToken) {
        throw new Error("No refresh token available to refresh.");
      }

      const response = await api.post<AuthTokens>("/auth/refresh-token", {
        refreshToken: currentRefreshToken,
      });

      // Poderia validar o retorno da API de refresh também se o backend tiver mais campos
      const { accessToken, refreshToken: newRefreshToken } = response.data;

      await SecureStorageService.saveToken(accessToken);
      if (newRefreshToken) {
        await SecureStorageService.saveRefreshToken(newRefreshToken);
      }

      console.log("Token de acesso refrescado com sucesso!");
      return accessToken;
    } catch (error) {
      console.error("Erro ao refrescar token:", error);
      await AuthService.logout();
      throw error;
    }
  },

  isAuthenticated: async (): Promise<boolean> => {
    const token = await SecureStorageService.getToken();
    return !!token;
  },
};
