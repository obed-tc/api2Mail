package main

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
	"github.com/joho/godotenv"
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
	ctx    = context.Background()
	client *redis.Client
)

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
		"<html><body><h1>¡Hola! 👋</h1>"+
			"<p>Este es un correo de prueba desde <strong>MailApi</strong> 📧</p>"+
			"<p>Si recibes este mensaje, ¡felicitaciones! El correo es válido ✅.</p>"+
			"<p>Por favor, guarda bien el token que se te ha generado, ya que lo necesitarás para realizar solicitudes autenticadas.<br> El token es: <strong>%s</strong> 🗝️</p>"+
			"<p>Para más información sobre cómo utilizar <strong>MailApi</strong>, haz clic en el siguiente enlace:</p>"+
			"<p><a href='https://www.mailapi.com/guia-de-uso' target='_blank'>Guía de Uso de MailApi 📚</a></p>"+
			"</body></html>", token)

	if err := es.send(email, password, email, subject, htmlBody); err != nil {
		log.Println("Error enviando el correo de prueba:", err)
		return fmt.Errorf("Credenciales incorrectas")
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

func (rs *RedisService) init() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error cargando el archivo .env: %v", err)
	}

	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		log.Fatal("REDIS_URL no está establecido en las variables de entorno")
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("Error al parsear la URL de Redis: %v", err)
	}

	client = redis.NewClient(opt)
}

func (rs *RedisService) saveObject(key string, obj interface{}) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("error al serializar el objeto: %v", err)
	}

	return client.Set(ctx, key, data, 0).Err()
}

func (rs *RedisService) getObject(key string, obj interface{}) error {
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
}

func (ah *AuthHandler) saveCredentials(c *gin.Context) {
	var newCredential Credential
	if err := c.BindJSON(&newCredential); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos"})
		return
	}

	// Generate token from password hash
	data := []byte(newCredential.Password)
	hash := sha3.Sum256(data)
	token := fmt.Sprintf("%x", hash[:])

	// send test email
	if err := ah.emailService.sendWelcomeEmail(newCredential.Email, newCredential.Password, token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// encrypt credentials
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

	// Save to Redis
	newInfoData := EncryptedInfo{
		Key:   fmt.Sprintf("%x", encryptedPassword),
		Value: fmt.Sprintf("%x", encryptedEmail),
	}

	if err := ah.redisService.saveObject(token, newInfoData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"token":   token,
		"message": "Te recomendamos guardar bien el token",
	})
}

func (ah *AuthHandler) sendEmailHandler(c *gin.Context) {
	// Validate Authorization header
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

	// Parse request
	var request EmailRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Error al leer el cuerpo de la solicitud"})
		return
	}

	// Get encrypted credentials from Redis
	var dataCredential EncryptedInfo
	if err := ah.redisService.getObject(token, &dataCredential); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// decrypt password
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

	// decrypt email
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

	// send email
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

func main() {
	// Initialize services
	redisService := &RedisService{}
	redisService.init()
	defer client.Close()

	emailService := &EmailService{}
	cryptoService := &CryptoService{}

	// Create handler with dependencies
	authHandler := &AuthHandler{
		emailService:  emailService,
		cryptoService: cryptoService,
		redisService:  redisService,
	}

	// Set up router
	router := gin.Default()

	// API routes
	router.POST("/credential/register", authHandler.saveCredentials)
	router.POST("/send-email", authHandler.sendEmailHandler)

	// Static files
	router.NoRoute(func(c *gin.Context) {
		http.ServeFile(c.Writer, c.Request, "./static/index.html")
	})

	// Start server
	log.Println("Servidor iniciado en el puerto 8080...")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Error al iniciar el servidor: %v", err)
	}
}