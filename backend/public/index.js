const socket = io('http://192.168.1.35:3000'); // Ajusta IP según tu red

socket.on('connect', () => {
  console.log('🟢 Conectado al servidor de monitoreo');
});

socket.on('disconnect', () => {
  console.log('🔴 Desconectado del servidor');
});