// env.d.ts
declare namespace NodeJS {
  interface ProcessEnv {
    readonly API_BASE_URL: string;
    readonly ANOTHER_SECRET_KEY: string;
    // Adicione todas as suas variáveis de ambiente aqui
  }
}
