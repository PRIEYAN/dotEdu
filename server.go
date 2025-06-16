package main

import (
	"context"
	"example/GOLANG/db"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type token struct {
	JWT string `json:"jwt"`
}

type Student struct {
	ID            string `json:"id"`
	CollegeID     string `json:"college_id"`
	CollegeName   string `json:"college_name"`
	StudentName   string `json:"student_name"`
	YearJoined    int    `json:"year_joined"`
	CollegeMailId string `json:"college_mail_id"`
	Passwrd       string `json:"password"`
	DeviceId      string `json:"deviceid"`
}

type StudentLogin struct {
	CollegeMailId string `json:"college_mail_id"`
	Passwrd       string `json:"password"`
	DeviceId      string `json:"deviceid"`
}

// for this nosql db
type chatHistory struct {
	SenderID   string `json:"sender_id"`
	ReceiverID string `json:"receiver_id"`
	Message    string `json:"message"`
	Timestamp  string `json:"timestamp"`
}

// mqtt client
var JWT_SECRET string
var mqttClient mqtt.Client

func initMQTT() {
	opts := mqtt.NewClientOptions().AddBroker("tcp://localhost:1883")
	opts.SetClientID("go_mqtt_client")
	mqttClient = mqtt.NewClient(opts)
	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}
}

// MongoDB client and collection
var MongoClient *mongo.Client
var MessagesCollection *mongo.Collection
var mongoURI string

func connectMongo() {
	ctx := context.Background()
	clientOptions := options.Client().ApplyURI(mongoURI)

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	MongoClient = client
	MessagesCollection = client.Database("chatapp").Collection("messages")
}

func home(c *gin.Context) {
	c.JSON(200, gin.H{"message": "Welcome to the Student Chat Application"})
}

func studentSignup(c *gin.Context) {
	var input Student
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	var existingMail string
	err := db.Conn.QueryRow(context.Background(),
		`SELECT CollegeMailId FROM Student WHERE CollegeMailId = $1`,
		input.CollegeMailId).Scan(&existingMail)
	if err == nil {
		c.JSON(409, gin.H{"message": "User already exists, please log in."})
		return
	}
	hashedPassword, hashErr := bcrypt.GenerateFromPassword([]byte(input.Passwrd), bcrypt.DefaultCost)
	if hashErr != nil {
		c.JSON(500, gin.H{"error": "Error hashing password"})
		return
	}
	_, err = db.Conn.Exec(context.Background(),
		`INSERT INTO Student (collegeid, collegename, studentname, yearjoined, collegemailid, passwrd,deviceid)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		input.CollegeID, input.CollegeName, input.StudentName,
		input.YearJoined, input.CollegeMailId, string(hashedPassword), input.DeviceId)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"college_mail_id": input.CollegeMailId,
		"device_id":       input.DeviceId,
		"exp":             time.Now().Add(7 * 24 * time.Hour).Unix(),
	})
	tokenString, tokenErr := token.SignedString([]byte(JWT_SECRET))
	if tokenErr != nil {
		c.JSON(500, gin.H{"error": "Error generating token"})
		return
	}
	c.JSON(200, gin.H{"message": "Account created successfully!", "user": input.StudentName, "jwtToken": tokenString})
}

func login(c *gin.Context) {
	var input StudentLogin
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	var storedPassword string
	err := db.Conn.QueryRow(context.Background(),
		`SELECT passwrd FROM Student WHERE collegemailid = $1 `,
		input.CollegeMailId).Scan(&storedPassword)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(input.Passwrd)) != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"college_mail_id": input.CollegeMailId,
		"device_id":       input.DeviceId,
		"exp":             time.Now().Add(7 * 24 * time.Hour).Unix(),
	})
	tokenString, tokenErr := token.SignedString([]byte(JWT_SECRET))
	if tokenErr != nil {
		c.JSON(500, gin.H{"error": "Error generating token"})
		return
	}
	_, err = db.Conn.Exec(context.Background(), `UPDATE Student SET deviceid = $1 WHERE collegemailid = $2`,
		input.DeviceId, input.CollegeMailId)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error updating device ID"})
		return
	}
	c.JSON(200, gin.H{"message": "Login successful!", "user": input.CollegeMailId, "jwtToken": tokenString})
}

func jwtverification(c *gin.Context) {
	var input token
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	token, err := jwt.Parse(input.JWT, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(JWT_SECRET), nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		collegeMail := claims["college_mail_id"]
		deviceId := claims["device_id"]
		var mailCheck, deviceCheck string
		err := db.Conn.QueryRow(
			context.Background(),
			`SELECT collegemailid, deviceid FROM student WHERE collegemailid = $1 AND deviceid = $2`,
			collegeMail, deviceId,
		).Scan(&mailCheck, &deviceCheck)
		if err != nil {
			c.JSON(401, gin.H{"error": "Session not valid or device mismatch"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"college_mail_id": collegeMail, "device_id": deviceId})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to decode token"})
}

func generateRoomTopic(user1, user2 string) string {
	users := []string{user1, user2}
	sort.Strings(users)
	return fmt.Sprintf("chat/%s_%s", users[0], users[1])
}

func sendMessage(c *gin.Context) {
	var input struct {
		SenderID   string    `json:"sender_id"`
		ReceiverID string    `json:"receiver_id"`
		Message    string    `json:"message"`
		Timestamp  time.Time `json:"timestamp"`
	}
	if err := c.BindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	input.Timestamp = time.Now()

	_, err := MessagesCollection.InsertOne(context.Background(), input)
	if err != nil {
		c.JSON(500, gin.H{"error": "DB insert failed"})
		return
	}
	topic := generateRoomTopic(input.SenderID, input.ReceiverID)
	mqttClient.Publish(topic, 0, false, input.Message)
	c.JSON(200, gin.H{"message": "Message sent and stored"})
}

func getMessages(c *gin.Context) {
	senderID := c.Query("senderId")
	receiverID := c.Query("receiverId")
	if senderID == "" || receiverID == "" {
		c.JSON(400, gin.H{"error": "Missing senderId or receiverId"})
		return
	}

	ctx := context.Background()

	filter := bson.M{
		"$or": []bson.M{
			{"sender_id": senderID, "receiver_id": receiverID},
			{"sender_id": receiverID, "receiver_id": senderID},
		},
	}

	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}})

	cursor, err := MessagesCollection.Find(ctx, filter, opts)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error fetching messages"})
		return
	}
	defer cursor.Close(ctx)

	var messages []chatHistory
	if err = cursor.All(ctx, &messages); err != nil {
		c.JSON(500, gin.H{"error": "Error decoding messages"})
		return
	}
	c.JSON(200, messages)
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	JWT_SECRET = os.Getenv("JWT_TOKEN")
	mongoURI = os.Getenv("MONGO_URI")
	connectMongo()
	initMQTT()

	router := gin.Default()
	db.ConnectDB()
	defer db.Conn.Close(context.Background())
	router.GET("/", home)
	router.POST("/studentSignup", studentSignup)
	router.POST("/login", login)
	router.POST("/sessionVerification", jwtverification)
	router.POST("/sendMessage", sendMessage)
	router.GET("/getMessages", getMessages)
	router.Run(":8080")
}
