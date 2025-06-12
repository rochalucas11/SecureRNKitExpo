// src/utils/sanitization.ts

/**
 * Escapa caracteres HTML especiais para prevenir XSS.
 * @param text O texto a ser escapado.
 * @returns O texto com caracteres HTML escapados.
 */
export const escapeHtml = (text: string): string => {
  if (typeof text !== "string") {
    return "";
  }
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

/**
 * Remove tags HTML básicas de uma string.
 * Nota: Para sanitização robusta de HTML (se você estiver exibindo HTML em WebViews),
 * considere uma biblioteca mais completa que analise o DOM (ex: dompurify para web,
 * mas para React Native com HTML puro, pode precisar de soluções mais específicas ou regex cuidadosas).
 * Esta função é um exemplo BÁSICO.
 * @param htmlString A string HTML a ser sanitizada.
 * @returns A string sem tags HTML.
 */
export const stripHtmlTags = (htmlString: string): string => {
  if (typeof htmlString !== "string") {
    return "";
  }
  // Regex simples para remover tags HTML
  return htmlString.replace(/<[^>]*>?/gm, "");
};

/**
 * Valida se um email está em um formato básico válido.
 * Considerar usar uma biblioteca de validação mais robusta (ex: `yup`, `zod`)
 * para validações mais complexas de esquemas de dados.
 * @param email O email a ser validado.
 * @returns True se o email for válido, false caso contrário.
 */
export const isValidEmail = (email: string): boolean => {
  if (typeof email !== "string") {
    return false;
  }
  // Regex para validação de email. Pode ser ajustado para ser mais ou menos rigoroso.
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Valida se uma string contém apenas caracteres alfanuméricos e espaços.
 * @param text O texto a ser validado.
 * @returns True se o texto for alfanumérico e contiver espaços, false caso contrário.
 */
export const isAlphanumericWithSpaces = (text: string): boolean => {
  if (typeof text !== "string") {
    return false;
  }
  const alphanumericRegex = /^[a-zA-Z0-9\s]*$/;
  return alphanumericRegex.test(text);
};

// Exemplo de uso:
// import { escapeHtml, stripHtmlTags } from '../utils/sanitization';
// <Text>{escapeHtml(userData.description)}</Text>
// <Text>{stripHtmlTags(htmlContentFromAPI)}</Text>
