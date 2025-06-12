module.exports = function (api) {
  api.cache(true);
  return {
    presets: ["babel-preset-expo"],
    plugins: [
      // Importante: este plugin deve vir ANTES de 'expo-router/babel'
      [
        "module:react-native-dotenv",
        {
          moduleName: "@env",
          path: ".env",
          blacklist: null,
          whitelist: null,
          safe: false,
          allowUndefined: true,
        },
      ],
      "expo-router/babel", // O plugin do Expo Router deve ser o último
    ],
  };
};
