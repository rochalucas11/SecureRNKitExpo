// src/utils/validationSchemas.ts
import { z } from "zod";

// Esquema para um usuário vindo da API
export const userSchema = z.object({
  id: z.string().uuid("ID do usuário deve ser um UUID válido."),
  name: z.string().min(2, "Nome deve ter no mínimo 2 caracteres."),
  email: z.string().email("Formato de email inválido."),
  age: z
    .number()
    .int()
    .positive("Idade deve ser um número inteiro positivo.")
    .optional(), // Opcional
  role: z.enum(["admin", "user", "guest"]).default("user"), // Enumeração de valores permitidos
});

// Tipo derivado do esquema Zod (para uso em TypeScript)
export type User = z.infer<typeof userSchema>;

// Esquema para dados de login (exemplo de validação de entrada)
export const loginSchema = z.object({
  email: z.string().email("Formato de email inválido."),
  password: z.string().min(6, "Senha deve ter no mínimo 6 caracteres."),
});

// Tipo derivado do esquema de login
export type LoginCredentials = z.infer<typeof loginSchema>;

/**
 * Função utilitária para validar dados contra um esquema Zod.
 * @param schema O esquema Zod a ser usado para validação.
 * @param data Os dados a serem validados.
 * @returns Os dados validados e tipados, ou lança um erro se a validação falhar.
 */
export const validateData = <T>(schema: z.ZodSchema<T>, data: unknown): T => {
  try {
    return schema.parse(data);
  } catch (error: any) {
    if (error instanceof z.ZodError) {
      console.error("Erro de validação de esquema:", error.errors);
      const errorMessages = error.errors
        .map((err) => `${err.path.join(".")} - ${err.message}`)
        .join("; ");
      throw new Error(`Erro de validação: ${errorMessages}`);
    }
    throw new Error(
      `Erro desconhecido na validação: ${error.message || error}`
    );
  }
};
