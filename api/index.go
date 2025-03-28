package handler

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/sha3"
)

// Constants and configuration
const (
	smtpServer = "smtp.gmail.com"
	smtpPort   = "587"
)

// Struct definitions
type EmailRequest struct {
	To       string `json:"to"`
	Subject  string `json:"subject"`
	HtmlBody string `json:"htmlBody"`
}

type Credential struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type EncryptedInfo struct {
	Key   string `json:"key"`   
	Value string `json:"value"`
}

// Global variables
var (
	ctx = context.Background()
	redisClient *redis.Client
)

// Inicialización global de Redis
func initRedis() *redis.Client {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		log.Fatal("REDIS_URL no está establecido en las variables de entorno")
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("Error al parsear la URL de Redis: %v", err)
	}

	return redis.NewClient(opt)
}

// Inicialización una vez al cargar el módulo
func init() {
	redisClient = initRedis()
}

// Email Service
type EmailService struct{}

func (es *EmailService) send(from, password, to, subject, htmlBody string) error {
	message := []byte("MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"Subject: " + subject + "\r\n" +
		"To: " + to + "\r\n" +
		"From: " + from + "\r\n" +
		"\r\n" +
		htmlBody)

	auth := smtp.PlainAuth("", from, password, smtpServer)
	return smtp.SendMail(smtpServer+":"+smtpPort, auth, from, []string{to}, message)
}

func (es *EmailService) sendWelcomeEmail(email, password, token string) error {
	subject := "¡Bienvenido a MailApi! 🎉"
	htmlBody := fmt.Sprintf(
		"<html><body><h1>¡Hola ! 👋</h1>"+
			"<p>Este es un correo de prueba desde <strong>MailApi</strong> 📧</p>"+
			"<p>Si recibes este mensaje, ¡felicitaciones! El correo es válido ✅.</p>"+
			"<p>Por favor, guarda bien el token que se te ha generado, ya que lo necesitarás para realizar solicitudes autenticadas.<br> El token es: <strong>%s</strong> 🗝️</p>"+
			"<p>Para más información sobre cómo utilizar <strong>MailApi</strong>, haz clic en el siguiente enlace:</p>"+
			"<p><a href='https://www.mailapi.com/guia-de-uso' target='_blank'>Guía de Uso de MailApi 📚</a></p>"+
			"</body></html>", token)

	if err := es.send(email, password, email, subject, htmlBody); err != nil {
		log.Println("Error enviando el correo de prueba para verificacion:", err)
		return fmt.Errorf("Credenciales incorrectas ")
	}

	return nil
}

// Crypto Service
type CryptoService struct{}

func (cs *CryptoService) deriveIVFromKey(key []byte) []byte {
	hash := sha3.New256()
	hash.Write(key)
	return hash.Sum(nil)[:aes.BlockSize]
}

func (cs *CryptoService) encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := cs.deriveIVFromKey(key)
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padText := append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)

	ciphertext := make([]byte, len(padText))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, padText)

	return append(iv, ciphertext...), nil
}

func (cs *CryptoService) decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := cs.deriveIVFromKey(key)
	ciphertext = ciphertext[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	cbc.CryptBlocks(plaintext, ciphertext)

	padding := plaintext[len(plaintext)-1]
	return plaintext[:len(plaintext)-int(padding)], nil
}

// Redis Service
type RedisService struct{}

func (rs *RedisService) saveObject(client *redis.Client, key string, obj interface{}) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("error al serializar el objeto: %v", err)
	}

	return client.Set(ctx, key, data, 0).Err()
}

func (rs *RedisService) getObject(client *redis.Client, key string, obj interface{}) error {
	data, err := client.Get(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("error al obtener el valor de Redis: %v", err)
	}
	return json.Unmarshal([]byte(data), obj)
}

// Handlers
type AuthHandler struct {
	emailService  *EmailService
	cryptoService *CryptoService
	redisService  *RedisService
	client        *redis.Client
}

func (ah *AuthHandler) saveCredentials(c *gin.Context) {
	var newCredential Credential
	if err := c.BindJSON(&newCredential); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos"})
		return
	}

	// Generar token a partir de hash de la contraseña
	data := []byte(newCredential.Password)
	hash := sha3.Sum256(data)
	token := fmt.Sprintf("%x", hash[:])

	// Enviar correo de prueba
	if err := ah.emailService.sendWelcomeEmail(newCredential.Email, newCredential.Password, token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Encriptar credenciales
	encryptedPassword, err := ah.cryptoService.encrypt([]byte(newCredential.Password), hash[:])
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al cifrar la contraseña"})
		return
	}

	encryptedEmail, err := ah.cryptoService.encrypt([]byte(newCredential.Email), hash[:])
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al cifrar el email"})
		return
	}

	// Guardar en Redis
	newInfoData := EncryptedInfo{
		Key:   fmt.Sprintf("%x", encryptedPassword),
		Value: fmt.Sprintf("%x", encryptedEmail),
	}

	if err := ah.redisService.saveObject(ah.client, token, newInfoData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"token":   token,
		"message": "Te recomendamos guardar bien el token",
	})
}

func (ah *AuthHandler) sendEmailHandler(c *gin.Context) {
	// Validar el encabezado de autorización
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
		return
	}

	parts := strings.Fields(authHeader)
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
		return
	}

	token := parts[1]
	tokenBytes, err := hex.DecodeString(token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token inválido"})
		return
	}

	// Parsear la solicitud
	var request EmailRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error al leer el cuerpo de la solicitud"})
		return
	}

	// Obtener credenciales encriptadas de Redis
	var dataCredential EncryptedInfo
	if err := ah.redisService.getObject(ah.client, token, &dataCredential); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Desencriptar contraseña
	encryptedPasswordBytes, err := hex.DecodeString(dataCredential.Key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error procesando credenciales"})
		return
	}

	decryptedPassword, err := ah.cryptoService.decrypt(encryptedPasswordBytes, tokenBytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al desencriptar la contraseña"})
		return
	}

	// Desencriptar email
	encryptedEmailBytes, err := hex.DecodeString(dataCredential.Value)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error procesando credenciales"})
		return
	}

	decryptedEmail, err := ah.cryptoService.decrypt(encryptedEmailBytes, tokenBytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al desencriptar el email"})
		return
	}

	// Enviar correo
	if err := ah.emailService.send(
		string(decryptedEmail),
		string(decryptedPassword),
		request.To,
		request.Subject,
		request.HtmlBody,
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Correo electrónico enviado exitosamente"})
}
func (ah *AuthHandler) serveIndexPage(c *gin.Context) {
	htmlContent := `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MailAPI - Servicio Profesional de Envío de Emails</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #FF7B25;
            --primary-dark: #CC5F0F;
            --accent-color: #FFA647;
            --background-dark: #121212;
            --background-darker: #0D0D0D;
            --sidebar-bg: #1E1E1E;
            --card-bg: #242424;
            --card-hover: #2E2E2E;
            --text-light: #F5F5F5;
            --text-muted: #B0B0B0;
            --success-color: #4CAF50;
            --warning-color: #FFC107;
            --error-color: #F44336;
            --border-radius: 12px;
            --box-shadow: 0 8px 16px rgba(0,0,0,0.2);
            --transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
        }

        /* Estilos personalizados para el scroll */
        ::-webkit-scrollbar {
            width: 12px;
            height: 12px;
        }

        ::-webkit-scrollbar-track {
            background: var(--background-darker);
        }

        ::-webkit-scrollbar-thumb {
            background-color: var(--primary-color);
            border-radius: 6px;
            border: 3px solid var(--background-darker);
        }

        ::-webkit-scrollbar-thumb:hover {
            background-color: var(--primary-dark);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            scrollbar-width: thin;
            scrollbar-color: var(--primary-color) var(--background-darker);
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            line-height: 1.7;
            background-color: var(--background-dark);
            color: var(--text-light);
            display: flex;
            min-height: 100vh;
        }

        /* Sidebar Styles */
        .sidebar {
            width: 280px;
            background-color: var(--sidebar-bg);
            height: 100vh;
            position: fixed;
            left: 0;
            top: 0;
            padding: 30px 20px;
            overflow-y: auto;
            border-right: 1px solid rgba(255,255,255,0.1);
            transition: var(--transition);
            z-index: 100;
        }

        .sidebar-logo {
            display: flex;
            align-items: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }

        .sidebar-logo i {
            color: var(--primary-color);
            font-size: 2.2rem;
            margin-right: 12px;
        }

        .sidebar-logo h1 {
            color: var(--text-light);
            font-size: 1.5rem;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .sidebar-logo span {
            color: var(--primary-color);
        }

        .sidebar-menu {
            list-style-type: none;
        }

        .sidebar-menu li {
            margin-bottom: 8px;
        }

        .sidebar-menu a {
            color: var(--text-muted);
            text-decoration: none;
            display: flex;
            align-items: center;
            padding: 12px 15px;
            border-radius: var(--border-radius);
            transition: var(--transition);
            font-weight: 500;
        }

        .sidebar-menu a:hover {
            background-color: rgba(255, 123, 37, 0.1);
            color: var(--primary-color);
            transform: translateX(5px);
        }

        .sidebar-menu a.active {
            background-color: rgba(255, 123, 37, 0.2);
            color: var(--primary-color);
            font-weight: 600;
        }

        .sidebar-menu a i {
            margin-right: 12px;
            font-size: 1.1rem;
            width: 20px;
            text-align: center;
        }

        /* Main Content Styles */
        .main-content {
            margin-left: 280px;
            width: calc(100% - 280px);
            padding: 40px;
        }

        .content-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
            flex-wrap: wrap;
            gap: 20px;
        }

        .content-header h2 {
            color: var(--text-light);
            font-size: 2rem;
            font-weight: 700;
        }

        .content-header h2 span {
            color: var(--primary-color);
        }

        .header-actions {
            display: flex;
            gap: 15px;
        }

        .header-actions a {
            display: inline-flex;
            align-items: center;
            padding: 10px 20px;
            background-color: rgba(255, 123, 37, 0.1);
            color: var(--primary-color);
            text-decoration: none;
            border-radius: var(--border-radius);
            font-weight: 500;
            transition: var(--transition);
            border: 1px solid rgba(255, 123, 37, 0.3);
        }

        .header-actions a:hover {
            background-color: rgba(255, 123, 37, 0.2);
            transform: translateY(-2px);
        }

        .header-actions a i {
            margin-right: 8px;
        }

        /* Card Styles */
        .card {
            background-color: var(--card-bg);
            border-radius: var(--border-radius);
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
            transition: var(--transition);
            border-left: 4px solid var(--primary-color);
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 24px rgba(0,0,0,0.3);
        }

        .card h3 {
            color: var(--primary-color);
            margin-bottom: 20px;
            font-size: 1.5rem;
            font-weight: 600;
            display: flex;
            align-items: center;
        }

        .card h3 i {
            margin-right: 12px;
        }

        .card p {
            color: var(--text-muted);
            margin-bottom: 20px;
            font-size: 1rem;
            line-height: 1.8;
        }

        /* Code Section Styles */
        .code-section {
            background-color: var(--background-darker);
            border-radius: var(--border-radius);
            padding: 20px;
            margin-top: 20px;
            overflow-x: auto;
            border: 1px solid rgba(255,255,255,0.1);
        }

        .code-section h4 {
            color: var(--accent-color);
            margin-bottom: 15px;
            font-size: 1.1rem;
            font-weight: 500;
            display: flex;
            align-items: center;
        }

        .code-section h4 i {
            margin-right: 10px;
        }

        .code-section pre {
            color: var(--text-light);
            font-family: 'Fira Code', monospace;
            font-size: 0.95rem;
            line-height: 1.6;
            white-space: pre-wrap;
            margin: 0;
        }

        .code-section code {
            display: block;
            padding: 15px;
            background-color: rgba(0,0,0,0.3);
            border-radius: 8px;
            overflow-x: auto;
        }

        /* Feature Grid Styles */
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 25px;
            margin-top: 30px;
        }

        .feature-card {
            background-color: var(--card-bg);
            padding: 30px;
            border-radius: var(--border-radius);
            text-align: center;
            transition: var(--transition);
            border-top: 3px solid var(--primary-color);
        }

        .feature-card:hover {
            transform: translateY(-8px);
            box-shadow: var(--box-shadow);
            background-color: var(--card-hover);
        }

        .feature-card i {
            color: var(--primary-color);
            font-size: 2.5rem;
            margin-bottom: 20px;
            background-color: rgba(255, 123, 37, 0.1);
            width: 70px;
            height: 70px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
        }

        .feature-card h4 {
            color: var(--text-light);
            margin-bottom: 15px;
            font-size: 1.2rem;
            font-weight: 600;
        }

        .feature-card p {
            color: var(--text-muted);
            font-size: 0.95rem;
            line-height: 1.7;
        }

        /* Tabs Styles */
        .tabs {
            display: flex;
            margin-bottom: 25px;
            gap: 10px;
            flex-wrap: wrap;
        }

        .tabs div {
            padding: 12px 20px;
            border-radius: 8px;
            background-color: var(--background-darker);
            color: var(--text-muted);
            transition: var(--transition);
            font-weight: 500;
            cursor: pointer;
            border: 1px solid rgba(255,255,255,0.1);
        }

        .tabs div:hover {
            background-color: rgba(255, 123, 37, 0.1);
            color: var(--primary-color);
        }

        .tabs .active-tab {
            background-color: var(--primary-color);
            color: var(--text-light);
            font-weight: 600;
        }

        .tab-content {
            display: none;
            animation: fadeIn 0.5s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .tab-content.active {
            display: block;
        }

        /* Link Styles */
        a.external-link {
            color: var(--accent-color);
            text-decoration: none;
            font-weight: 500;
            transition: var(--transition);
            display: inline-flex;
            align-items: center;
        }

        a.external-link:hover {
            color: var(--primary-color);
            text-decoration: underline;
        }

        a.external-link i {
            margin-left: 8px;
            font-size: 0.9rem;
        }

        /* Badge Styles */
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-left: 10px;
        }

        .badge-new {
            background-color: var(--accent-color);
            color: #000;
        }

        .badge-updated {
            background-color: var(--warning-color);
            color: #000;
        }

        /* Responsive Styles */
        @media (max-width: 992px) {
            .sidebar {
                width: 240px;
                padding: 20px 15px;
            }
            
            .main-content {
                margin-left: 240px;
                width: calc(100% - 240px);
                padding: 30px;
            }
        }

        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
                width: 280px;
                z-index: 1000;
            }
            
            .sidebar.active {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
                width: 100%;
                padding: 25px;
            }
            
            .menu-toggle {
                display: block;
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 1001;
                background-color: var(--primary-color);
                color: white;
                width: 50px;
                height: 50px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 1.5rem;
                cursor: pointer;
                box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            }
        }

        /* Utility Classes */
        .mt-20 { margin-top: 20px; }
        .mb-20 { margin-bottom: 20px; }
        .text-center { text-align: center; }
        .text-accent { color: var(--accent-color); }
    </style>
</head>
<body>
    <div class="menu-toggle" onclick="toggleSidebar()">
        <i class="fas fa-bars"></i>
    </div>

    <aside class="sidebar">
        <div class="sidebar-logo">
            <i class="fas fa-paper-plane"></i>
            <h1>Mail<span>API</span></h1>
        </div>

        <ul class="sidebar-menu">
            <li><a href="#inicio" ><i class="fas fa-home"></i> Inicio</a></li>
            <li><a href="#quickstart"><i class="fas fa-rocket"></i> Comenzar rápido</a></li>
            <li><a href="#autenticacion"><i class="fas fa-key"></i> Obtener Token</a></li>
            <li><a href="#envio-correo"><i class="fas fa-envelope"></i> Envío de Emails</a></li>
            <li><a href="#soporte"><i class="fas fa-life-ring"></i> Soporte</a></li>
        </ul>
    </aside>

    <main class="main-content">
        <header class="content-header">
            <h2>Documentación de <span>MailAPI</span></h2>
            <div class="header-actions">
                <a href="https://github.com/obed-tc/api2Mail" target="_blank" class="external-link"><i class="fab fa-github"></i> Ver en GitHub</a>
            </div>
        </header>

        <section id="inicio" class="card">
            <h3><i class="fas fa-home"></i> Bienvenido a MailAPI</h3>
            <p>MailAPI es un servicio profesional de envío de correos electrónicos diseñado para desarrolladores que necesitan integración sencilla y alta confiabilidad en sus aplicaciones.</p>
            <p>Con nuestra API RESTful, puedes enviar correos electrónicos con solo unas pocas líneas de código, sin preocuparte por la infraestructura de envío.</p>
            
            <div class="feature-grid mt-20">
                <div class="feature-card">
                    <i class="fas fa-shield-alt"></i>
                    <h4>Seguridad</h4>
                    <p>Autenticación con token seguro para proteger tus envíos.</p>
                </div>
                <div class="feature-card">
                    <i class="fas fa-tachometer-alt"></i>
                    <h4>Fácil Integración</h4>
                    <p>Endpoints simples y documentación clara para una implementación rápida.</p>
                </div>
                <div class="feature-card">
                    <i class="fas fa-envelope"></i>
                    <h4>HTML Soportado</h4>
                    <p>Envía correos con contenido HTML personalizado para mejor engagement.</p>
                </div>
            </div>
        </section>

        <section id="quickstart" class="card">
            <h3><i class="fas fa-rocket"></i> Comenzar Rápido</h3>
            <p>Envía tu primer email en menos de 5 minutos con nuestro ejemplo de código listo para usar. Solo necesitas obtener tu token y hacer una petición HTTP.</p>

            <div class="tabs">
                <div class="active-tab" onclick="showTab('quickstart-python')">Python</div>
                <div onclick="showTab('quickstart-javascript')">JavaScript</div>
                <div onclick="showTab('quickstart-curl')">cURL</div>
            </div>

            <div id="quickstart-python" class="tab-content active">
                <div class="code-section">
                    <h4><i class="fas fa-code"></i> Ejemplo en Python</h4>
                    <pre><code>import requests

# Primero obtén tu token
register_url = "https://api2mail.vercel.app/credential/register"
register_data = {
    "email": "tu_email@ejemplo.com",
    "password": "tu_contraseña_segura"
}

register_response = requests.post(register_url, json=register_data)
token = register_response.json()["token"]

# Luego envía un email
send_url = "https://api2mail.vercel.app/send-email"
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

email_data = {
    "to": "destinatario@ejemplo.com",
    "subject": "Asunto del correo",
    "htmlBody": "&lt;h1&gt;Hola&lt;/h1&gt;&lt;p&gt;Este es un correo de prueba.&lt;/p&gt;"
}

send_response = requests.post(send_url, headers=headers, json=email_data)
print(send_response.json())</code></pre>
                </div>
            </div>

            <div id="quickstart-javascript" class="tab-content">
                <div class="code-section">
                    <h4><i class="fas fa-code"></i> Ejemplo en JavaScript</h4>
                    <pre><code>// Primero obtén tu token
const register = async () => {
  const registerResponse = await fetch("https://api2mail.vercel.app/credential/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      email: "tu_email@ejemplo.com",
      password: "tu_contraseña_segura"
    })
  });
  
  const registerData = await registerResponse.json();
  return registerData.token;
};

// Luego envía un email
const sendEmail = async (token) => {
  const sendResponse = await fetch("https://api2mail.vercel.app/send-email", {
    method: "POST",
    headers: {
      "Authorization": Bearer ${token},
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      to: "destinatario@ejemplo.com",
      subject: "Asunto del correo",
      htmlBody: "&lt;h1&gt;Hola&lt;/h1&gt;&lt;p&gt;Este es un correo de prueba.&lt;/p&gt;"
    })
  });
  
  return await sendResponse.json();
};

// Ejecutar el flujo
register().then(token => {
  sendEmail(token).then(response => {
    console.log(response);
  });
});</code></pre>
                </div>
            </div>

            <div id="quickstart-curl" class="tab-content">
                <div class="code-section">
                    <h4><i class="fas fa-code"></i> Ejemplo con cURL</h4>
                    <pre><code># Primero obtén tu token
curl -X POST \
  https://api2mail.vercel.app/credential/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "tu_email@ejemplo.com",
    "password": "tu_contraseña_segura"
  }'

# Luego usa el token para enviar un email
curl -X POST \
  https://api2mail.vercel.app/send-email \
  -H "Authorization: Bearer TU_TOKEN_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "destinatario@ejemplo.com",
    "subject": "Asunto del correo",
    "htmlBody": "<h1>Hola</h1><p>Este es un correo de prueba.</p>"
  }'</code></pre>
                </div>
            </div>
        </section>

        <section id="autenticacion" class="card">
            <h3><i class="fas fa-key"></i> Obtener Token de Acceso</h3>
            <p>Para usar la API, primero necesitas obtener un token de acceso mediante el endpoint de registro.</p>
            
            <div class="code-section">
                <h4><i class="fas fa-link"></i> Endpoint de Registro</h4>
                <pre><code>POST https://api2mail.vercel.app/credential/register</code></pre>
            </div>
            
            <div class="code-section mt-20">
                <h4><i class="fas fa-code"></i> Cuerpo de la Solicitud</h4>
                <pre><code>{
    "email": "tu_email@ejemplo.com",
    "password": "tu_contraseña_segura"
}</code></pre>
            </div>
            
            <div class="code-section mt-20">
                <h4><i class="fas fa-check-circle"></i> Respuesta Exitosa</h4>
                <pre><code>{
    "message": "Te recomendamos guardar bien el token",
    "token": "*********************************************fe8ca967a264fad"
}</code></pre>
            </div>
            
            <div class="mt-20">
                <h4><i class="fas fa-shield-alt"></i> Recomendaciones de Seguridad</h4>
                <ul style="color: var(--text-muted); margin-top: 15px; line-height: 1.8; padding-left: 20px;">
                    <li>Guarda tu token en un lugar seguro</li>
                    <li>No compartas tu token con nadie</li>
                    <li>Usa contraseñas seguras para el registro</li>
                    <li>Si comprometes tu token, registra una nueva cuenta</li>
                </ul>
            </div>
        </section>

        <section id="envio-correo" class="card">
            <h3><i class="fas fa-envelope"></i> Envío de Emails</h3>
            <p>Una vez que tienes tu token, puedes usarlo para enviar correos electrónicos con contenido HTML personalizado.</p>
            
            <div class="code-section">
                <h4><i class="fas fa-link"></i> Endpoint de Envío</h4>
                <pre><code>POST https://api2mail.vercel.app/send-email</code></pre>
            </div>
            
            <div class="code-section mt-20">
                <h4><i class="fas fa-code"></i> Encabezados Requeridos</h4>
                <pre><code>Authorization: Bearer TU_TOKEN_AQUI
Content-Type: application/json</code></pre>
            </div>
            
            <div class="code-section mt-20">
                <h4><i class="fas fa-code"></i> Cuerpo de la Solicitud</h4>
                <pre><code>{
    "to": "destinatario@ejemplo.com",
    "subject": "Asunto del correo",
    "htmlBody": "&lt;h1 style='color: blue;'&gt;Hola&lt;/h1&gt;&lt;p&gt;Este es un correo con &lt;strong&gt;HTML&lt;/strong&gt;.&lt;/p&gt;"
}</code></pre>
            </div>
            
            <div class="code-section mt-20">
                <h4><i class="fas fa-check-circle"></i> Respuesta Exitosa</h4>
                <pre><code>{
    "message": "Correo electrónico enviado exitosamente"
}</code></pre>
            </div>
            
            <div class="mt-20">
                <h4><i class="fas fa-lightbulb"></i> Consejos</h4>
                <ul style="color: var(--text-muted); margin-top: 15px; line-height: 1.8; padding-left: 20px;">
                    <li>Puedes usar HTML completo en el campo <code>htmlBody</code></li>
                    <li>Incluye estilos inline para mejor compatibilidad</li>
                    <li>Prueba siempre con una dirección de correo propia primero</li>
                    <li>Mantén tu token seguro en cada solicitud</li>
                </ul>
            </div>
        </section>

        <section id="soporte" class="card">
            <h3><i class="fas fa-life-ring"></i> Soporte</h3>
            <p>Si necesitas ayuda con la API o tienes alguna pregunta, puedes contactarnos de las siguientes formas:</p>
            
            <div class="feature-grid mt-20">
                <div class="feature-card">
                    <i class="fab fa-github"></i>
                    <h4>GitHub</h4>
                    <p>Reporta issues o consulta el código en nuestro <a href="https://github.com/obed-tc/api2Mail" class="external-link">repositorio oficial <i class="fas fa-external-link-alt"></i></a>.</p>
                </div>
                <div class="feature-card">
                    <i class="fas fa-code-branch"></i>
                    <h4>Contribuir</h4>
                    <p>Si eres desarrollador, puedes contribuir al proyecto mediante pull requests.</p>
                </div>
                <div class="feature-card">
                    <i class="fas fa-question-circle"></i>
                    <h4>Preguntas</h4>
                    <p>Para preguntas específicas, abre un issue en GitHub con la etiqueta "question".</p>
                </div>
            </div>
        </section>
    </main>

     <script>
        // Función mínima para mostrar pestañas
        function showTab(tabId) {
            const tabs = document.querySelectorAll('.tab-content');
            const tabButtons = document.querySelectorAll('.tabs div');

            tabs.forEach(tab => {
                tab.classList.remove('active');
            });

            tabButtons.forEach(button => {
                button.classList.remove('active-tab');
            });

            document.getElementById(tabId).classList.add('active');
            event.currentTarget.classList.add('active-tab');
        }

        // Función mínima para el menú móvil
        function toggleSidebar() {
            const sidebar = document.querySelector('.sidebar');
            sidebar.classList.toggle('active');
        }
    </script> 
</body>
</html>

`
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, htmlContent)
}

// Modificación del handler para Vercel
func Handler(w http.ResponseWriter, r *http.Request) {
	// Configurar Gin en modo de producción
	gin.SetMode(gin.ReleaseMode)

	// Crear router
	router := gin.New()
	router.Use(gin.Recovery())

	// Servicios
	emailService := &EmailService{}
	cryptoService := &CryptoService{}
	redisService := &RedisService{}

	// Handler de autenticación
	authHandler := &AuthHandler{
		emailService:  emailService,
		cryptoService: cryptoService,
		redisService:  redisService,
		client:        redisClient,
	}

	// Rutas
	router.POST("/credential/register", authHandler.saveCredentials)
	router.POST("/send-email", authHandler.sendEmailHandler)
	router.GET("/", authHandler.serveIndexPage)

	// Manejar solicitud
	router.ServeHTTP(w, r)
}