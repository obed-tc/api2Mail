# 📧 MailAPI - Servicio de Envío de Correos Electrónicos en Go

MailAPI es un servicio ligero y eficiente para el envío de correos electrónicos mediante una API RESTful, desarrollado completamente en Go. Perfecto para integración en tus aplicaciones backend.

## ✨ Características Principales

- 🚀 **Rendimiento de Go**: Alta velocidad y bajo consumo de recursos
- 📧 **Envío de correos HTML**: Soporte completo para contenido HTML en emails
- 🔐 **Autenticación simple**: Basada en tokens seguros
- 🌐 **API RESTful**: Endpoints simples y bien documentados
- ⚡ **Fácil despliegue**: Configuración mínima requerida

## 🛠️ Tecnologías Utilizadas

- **Go 1.18+**: Lenguaje principal del proyecto
- **Gin**: Framework web para el router HTTP
- **Vercel**: Plataforma de despliegue
- **SMTP**: Protocolo para envío de correos

## 🚀 Comenzar

### Requisitos Previos

- Go 1.18 o superior instalado
- Cuenta en Vercel para despliegue (opcional)
- Servidor SMTP configurado (o usar uno como SendGrid, Mailgun, etc.)

### Instalación Local

1. Clona el repositorio:
   ```bash
   git clone https://github.com/obed-tc/api2Mail.git
   cd api2Mail
   ```

2. Configura las variables de entorno:
   ```bash
   cp .env.example .env
   # Edita el .env con tus credenciales SMTP
   ```

3. Instala las dependencias y ejecuta:
   ```bash
   go mod download
   go run main.go
   ```

## 📚 Documentación de la API

### Autenticación

Primero necesitas obtener un token de acceso:

**Endpoint**:
```
POST /credential/register
```

**Cuerpo**:
```json
{
    "email": "tu@email.com",
    "password": "tu_contraseña_segura"
}
```

**Respuesta Exitosa**:
```json
{
    "message": "Te recomendamos guardar bien el token",
    "token": "tu_token_de_acceso"
}
```

### Envío de Emails

Una vez obtenido el token:

**Endpoint**:
```
POST /send-email
```

**Headers**:
```
Authorization: Bearer tu_token_de_acceso
Content-Type: application/json
```

**Cuerpo**:
```json
{
    "to": "destinatario@email.com",
    "subject": "Asunto del correo",
    "htmlBody": "<h1>Hola</h1><p>Este es un correo de prueba</p>"
}
```

**Respuesta Exitosa**:
```json
{
    "message": "Correo electrónico enviado exitosamente"
}
```

## 🤝 Contribuir

Las contribuciones son bienvenidas. Sigue estos pasos:

1. Haz un fork del proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Haz commit de tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Haz push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📜 Licencia

Distribuido bajo la licencia MIT. Consulta `LICENSE` para más información.

## 📬 Contacto

ObedCT_ - [@twitter](https://x.com/ObedCT_) - 

**Enlace del Proyecto**: [https://github.com/obed-tc/api2Mail](https://github.com/obed-tc/api2Mail)
