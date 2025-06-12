// app/_layout.tsx (Exemplo de uso da detecção de Root/Jailbreak)
import { Stack } from "expo-router";
import { useEffect } from "react";
import { Alert } from "react-native";
import { DeviceSecurityService } from "../SecureRNKitExpo/src/services/deviceSecurity"; // Caminho correto

export default function RootLayout() {
  useEffect(() => {
    const checkSecurity = async () => {
      const isCompromised = await DeviceSecurityService.isDeviceCompromised();
      if (isCompromised) {
        Alert.alert(
          "Alerta de Segurança",
          "Este dispositivo parece estar comprometido (rooted/jailbroken). Algumas funcionalidades podem ser desativadas por segurança."
          // Você pode adicionar um botão para sair do app ou desabilitar funcionalidades sensíveis
          // [{ text: 'OK', onPress: () => { /* Desabilitar funcionalidades ou sair do app */ } }]
        );
      }

      const isEmulator = await DeviceSecurityService.isEmulator();
      // Faça algo se estiver emulador, se necessário para depuração/testes
    };

    checkSecurity();
  }, []);

  return (
    <Stack>
      <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
      <Stack.Screen name="modal" options={{ presentation: "modal" }} />
    </Stack>
  );
}
