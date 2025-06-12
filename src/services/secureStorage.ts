// src/services/secureStorage.ts
import * as SecureStore from "expo-secure-store";

export const SecureStorageService = {
  /**
   * Salva o token JWT de forma segura.
   * @param token O token JWT a ser salvo.
   */
  saveToken: async (token: string): Promise<void> => {
    try {
      await SecureStore.setItemAsync(process.env.TOKEN_KEY, token);
      console.log("JWT salvo com sucesso no SecureStore.");
    } catch (error) {
      console.error("Erro ao salvar JWT no SecureStore:", error);
      throw error;
    }
  },

  /**
   * Obtém o token JWT de forma segura.
   * @returns O token JWT ou null se não encontrado.
   */
  getToken: async (): Promise<string | null> => {
    try {
      const token = await SecureStore.getItemAsync(process.env.TOKEN_KEY);
      return token;
    } catch (error) {
      console.error("Erro ao obter JWT do SecureStore:", error);
      return null;
    }
  },

  /**
   * Deleta o token JWT de forma segura.
   */
  deleteToken: async (): Promise<void> => {
    try {
      await SecureStore.deleteItemAsync(process.env.TOKEN_KEY);
      console.log("JWT deletado com sucesso do SecureStore.");
    } catch (error) {
      console.error("Erro ao deletar JWT do SecureStore:", error);
      throw error;
    }
  },

  // --- Opcional: Métodos para Refresh Token ---
  saveRefreshToken: async (token: string): Promise<void> => {
    try {
      await SecureStore.setItemAsync(process.env.REFRESH_TOKEN_KEY, token);
      console.log("Refresh Token salvo com sucesso no SecureStore.");
    } catch (error) {
      console.error("Erro ao salvar Refresh Token no SecureStore:", error);
      throw error;
    }
  },

  getRefreshToken: async (): Promise<string | null> => {
    try {
      const token = await SecureStore.getItemAsync(
        process.env.REFRESH_TOKEN_KEY
      );
      return token;
    } catch (error) {
      console.error("Erro ao obter Refresh Token do SecureStore:", error);
      return null;
    }
  },

  deleteRefreshToken: async (): Promise<void> => {
    try {
      await SecureStore.deleteItemAsync(process.env.REFRESH_TOKEN_KEY);
      console.log("Refresh Token deletado com sucesso do SecureStore.");
    } catch (error) {
      console.error("Erro ao deletar Refresh Token do SecureStore:", error);
      throw error;
    }
  },
};
