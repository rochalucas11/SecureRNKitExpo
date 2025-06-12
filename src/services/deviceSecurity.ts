// src/services/deviceSecurity.ts
import DeviceInfo from "react-native-device-info";

export const DeviceSecurityService = {
  /**
   * Verifica se o dispositivo está rooted (Android) ou jailbroken (iOS).
   * @returns Promise<boolean> - True se o dispositivo estiver comprometido, false caso contrário.
   */
  isDeviceCompromised: async (): Promise<boolean> => {
    try {
      const isRooted = await DeviceInfo.isRooted();
      if (isRooted) {
        console.warn(
          "Alerta de Segurança: Dispositivo está ROOTED/JAILBROKEN!"
        );
      }
      return isRooted;
    } catch (error) {
      console.error("Erro ao verificar status do dispositivo:", error);
      // Em caso de erro na verificação, é mais seguro assumir que o dispositivo pode estar comprometido
      // ou apenas registrar o erro e continuar, dependendo da sua política de segurança.
      return false; // Ou true, dependendo da sua tolerância a falhas na detecção
    }
  },

  // Outras verificações (opcional, mas bom ter em mente para o futuro)
  /**
   * Verifica se o app está sendo executado em um emulador/simulador.
   * @returns Promise<boolean>
   */
  isEmulator: async (): Promise<boolean> => {
    try {
      const isEmulator = await DeviceInfo.isEmulator();
      if (isEmulator) {
        console.info("Aviso: Aplicativo rodando em EMULADOR/SIMULADOR.");
      }
      return isEmulator;
    } catch (error) {
      console.error("Erro ao verificar se é emulador:", error);
      return false;
    }
  },

  /**
   * Verifica se o modo de depuração está ativado.
   * EM PRODUÇÃO, NUNCA DEVE ESTAR ATIVO.
   * @returns boolean
   */
  isDebugMode: (): boolean => {
    const isDebug = __DEV__; // Variável global do React Native para ambiente de desenvolvimento
    if (isDebug) {
      console.warn(
        "Alerta de Segurança: Aplicativo em MODO DE DEBUG. Desative em produção!"
      );
    }
    return isDebug;
  },
};
