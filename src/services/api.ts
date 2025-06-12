// src/services/api.ts (ATUALIZADO)
import axios from "axios";
import { SecureStorageService } from "./secureStorage"; // Importe o serviço de armazenamento seguro
// import { router } from 'expo-router'; // Para redirecionar para tela de login

const api = axios.create({
  baseURL: process.env.API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

let isRefreshing = false;
let failedQueue: {
  resolve: (value?: unknown) => void;
  reject: (reason?: any) => void;
}[] = [];

const processQueue = (error: any | null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(); // Resolva com o novo token ou null se não houver
    }
  });
  failedQueue = [];
};

// Interceptor de Requisição: Adiciona o token JWT (se existir)
api.interceptors.request.use(
  async (config) => {
    const token = await SecureStorageService.getToken(); // Obtém o token do SecureStore
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Interceptor de Resposta: Lida com erros de autenticação e refresh token
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Se o erro for 401 e a requisição ainda não foi tentada novamente E não estamos refrescando
    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !isRefreshing
    ) {
      originalRequest._retry = true;
      isRefreshing = true;

      // Retorne uma nova Promise que será resolvida/rejeitada
      // assim que o token for refrescado ou o refresh falhar
      return new Promise(async (resolve, reject) => {
        // Adicione a requisição original à fila de requisições falhas
        failedQueue.push({ resolve, reject });

        try {
          const refreshToken = await SecureStorageService.getRefreshToken();

          if (!refreshToken) {
            console.warn("No refresh token found. Logging out...");
            // await SecureStorageService.deleteToken();
            // await SecureStorageService.deleteRefreshToken();
            // router.replace('/login'); // Redireciona para login
            processQueue(new Error("No refresh token available."));
            reject(error); // Rejeita a requisição original
            return;
          }

          // **AQUI: Chamar o endpoint de refresh token do seu backend**
          // Exemplo (você precisará criar este endpoint no seu backend):
          // const refreshResponse = await axios.post(`${API_BASE_URL}/auth/refresh-token`, { refreshToken });
          // const newAccessToken = refreshResponse.data.accessToken;
          // const newRefreshToken = refreshResponse.data.refreshToken; // Se o backend retornar um novo refresh token

          // --- Simulando o refresh token (REMOVA ISSO NA PRODUÇÃO) ---
          console.log("Simulando refresh token...");
          await new Promise((res) => setTimeout(res, 1000)); // Simula requisição de rede
          const newAccessToken = "NEW_GENERATED_JWT_TOKEN";
          const newRefreshToken = "NEW_GENERATED_REFRESH_TOKEN";
          // --- FIM DA SIMULAÇÃO ---

          await SecureStorageService.saveToken(newAccessToken);
          await SecureStorageService.saveRefreshToken(newRefreshToken); // Salva o novo refresh token

          // Atualiza o header da requisição original com o novo token e tenta novamente
          originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
          processQueue(null); // Processa todas as requisições na fila
          resolve(api(originalRequest)); // Tenta a requisição original novamente
        } catch (refreshError) {
          console.error("Error refreshing token:", refreshError);
          // Limpa tokens e redireciona para login em caso de falha no refresh
          // await SecureStorageService.deleteToken();
          // await SecureStorageService.deleteRefreshToken();
          // router.replace('/login'); // Redireciona para login
          processQueue(refreshError); // Notifica as requisições na fila do erro
          reject(refreshError); // Rejeita a requisição original
        } finally {
          isRefreshing = false;
        }
      });
    }

    // Se o erro 401 acontecer quando já estivermos tentando refrescar,
    // ou se não for um 401, apenas propaga o erro.
    return Promise.reject(error);
  }
);

export default api;
