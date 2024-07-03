package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

var (
	bot             *tgbotapi.BotAPI
	mongoClient     *mongo.Client
	usersCollection *mongo.Collection
)

type User struct {
	UserID                  int64   `bson:"user_id"`
	LastChainCleanDate      string  `bson:"last_chain_clean_date"`
	ChainCleanInterval      int     `bson:"chain_clean_interval"`
	LastChainLubeDate       string  `bson:"last_chain_lube_date"`
	ChainLubeInterval       int     `bson:"chain_lube_interval"`
	StravaAccessToken       string  `bson:"strava_access_token"`
	StravaRefreshToken      string  `bson:"strava_refresh_token"`
	StravaTokenExpiry       int64   `bson:"strava_token_expiry"`
	TotalDistanceAfterClean float64 `bson:"total_distance_after_clean"`
	TotalDistanceAfterLube  float64 `bson:"total_distance_after_lube"`
}

type Activity struct {
	Distance  float64 `json:"distance"`
	Type      string  `json:"type"`
	StartDate string  `json:"start_date"`
}

type SurveyState struct {
	UserID      int64 `bson:"user_id"`
	CurrentStep int   `bson:"current_step"`
}

var Questions = []string{
	"When did you last clean the chain? (enter YYYY-MM-DD, e.g., 1991-11-08)",
	"After how many kilometers do you clean the chain? (enter an integer)",
	"When did you last lube the chain? (enter YYYY-MM-DD, e.g., 1991-11-08)",
	"After how many kilometers do you lube the chain? (enter an integer)",
}

func main() {
	var err error

	if err = godotenv.Load(); err != nil {
		log.Println("Error loading .env file")
	}

	requiredEnvVars := []string{
		"TELEGRAM_BOT_TOKEN",
		"MONGODB_URI",
		"STRAVA_CLIENT_ID",
		"STRAVA_CLIENT_SECRET",
		"STRAVA_AUTH_URL",
		"STRAVA_REDIRECT_URI",
		"PORT",
	}

	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			log.Fatalf("Environment variable %s must be set", envVar)
		}
	}

	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	mongoURI := os.Getenv("MONGODB_URI")
	port := os.Getenv("PORT")

	bot, err = tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Fatalf("Failed to create Telegram bot: %v", err)
	}

	bot.Debug = true

	mongoClient, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	err = mongoClient.Ping(context.TODO(), readpref.Primary())
	if err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	usersCollection = mongoClient.Database("chainbot").Collection("users")

	go startStravaDataFetcher()

	router := gin.Default()
	router.Static("/html", "./html")
	router.LoadHTMLGlob("html/*")
	router.GET("/", showWelcomePage)
	router.GET("/auth/strava/callback", handleStravaCallback)

	if port == "" {
		port = "8080"
	}

	go func() {
		if err := router.Run(":" + port); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates, err := bot.GetUpdatesChan(u)
	if err != nil {
		log.Fatalf("Failed to get updates channel: %v", err)
	}

	for update := range updates {
		if update.Message != nil {
			handleUpdate(update.Message)
		}
	}
}

func handleUpdate(message *tgbotapi.Message) {
	userID := int64(message.From.ID)
	text := message.Text

	user, err := getUserByID(userID)
	if err != nil {
		user = &User{UserID: userID}
		createUser(user)
	}

	if message.IsCommand() {
		switch message.Command() {
		case "start":
			handleStartCommand(userID)
		default:
			sendMessage(userID, "I don't know that command")
		}
		return
	}

	switch text {
	case "🚿 I cleaned the chain":
		handleCleanChain(user)
	case "🛢️ I lubed the chain":
		handleLubeChain(user)
	case "🔧 Change chain lube interval":
		sendMessage(userID, "Enter new chain lube interval (in km):")
		updateSurveyState(userID, 5)
	case "🔧 Change chain clean interval":
		sendMessage(userID, "Enter new chain clean interval (in km):")
		updateSurveyState(userID, 6)
	case "❌ Forget me":
		deleteUserByID(userID)
		sendMessage(userID, "Your data has been deleted.\n\nUse /start to run again.")
	case "📊 Show Stats":
		showChainStatus(userID)
	default:
		state, err := getSurveyStateByID(userID)
		if err == nil {
			switch state.CurrentStep {
			case 5:
				if interval, err := strconv.Atoi(text); err == nil && interval > 0 {
					updateUserField(userID, "chain_lube_interval", interval)
					sendMessage(userID, "Chain lube interval updated.")
					showChainStatus(userID)
				} else {
					sendMessage(userID, "Invalid input. Please enter a positive integer.")
				}
			case 6:
				if interval, err := strconv.Atoi(text); err == nil && interval > 0 {
					updateUserField(userID, "chain_clean_interval", interval)
					sendMessage(userID, "Chain clean interval updated.")
					showChainStatus(userID)
				} else {
					sendMessage(userID, "Invalid input. Please enter a positive integer.")
				}
			default:
				handleSurvey(user, text)
			}
		} else {
			handleSurvey(user, text)
		}
	}
}

func handleCleanChain(user *User) {
	user.LastChainCleanDate = time.Now().Format("2006-01-02")
	user.TotalDistanceAfterClean = 0
	user.LastChainLubeDate = time.Now().Format("2006-01-02")
	user.TotalDistanceAfterLube = 0
	updateUser(user)
	sendMessage(user.UserID, "Chain clean date updated to today.")
	showChainStatus(user.UserID)
}

func handleLubeChain(user *User) {
	user.LastChainLubeDate = time.Now().Format("2006-01-02")
	user.TotalDistanceAfterLube = 0
	updateUser(user)
	sendMessage(user.UserID, "Chain lube date updated to today.")
	showChainStatus(user.UserID)
}

func handleStartCommand(userID int64) {
	user, err := getUserByID(userID)
	if err != nil || user.StravaAccessToken == "" {
		sendStravaAuthLink(userID)
	} else {
		startSurvey(userID)
	}
}

func isDateValid(dateStr string) (bool, string) {
	parsedDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return false, "Invalid date format. Please enter the date in YYYY-MM-DD format."
	}

	now := time.Now()
	oneMonthAgo := now.AddDate(0, -1, 0)

	if parsedDate.After(now) {
		return false, "The date cannot be in the future. Please enter a valid date."
	}

	if parsedDate.Before(oneMonthAgo) {
		return false, "It's been too long since you last cleaned/lubed your chain! Service your bike and come back! Use /start to run again."
	}

	return true, ""
}

func startSurvey(userID int64) {
	resetSurveyState(userID)
	sendMessage(userID, "When did you last clean the chain? (enter YYYY-MM-DD, e.g., 1991-11-08)")
}

func sendStravaAuthLink(userID int64) {
	stravaAuthURL := fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=%s&scope=read,activity:read&state=%d",
		os.Getenv("STRAVA_AUTH_URL"),
		os.Getenv("STRAVA_CLIENT_ID"),
		os.Getenv("STRAVA_REDIRECT_URI"),
		userID,
	)
	sendMessage(userID, "Please authorize the bot with Strava: "+stravaAuthURL)
}

func sendMessage(userID int64, text string) {
	msg := tgbotapi.NewMessage(userID, text)
	bot.Send(msg)
}

func getUserByID(userID int64) (*User, error) {
	var user User
	err := usersCollection.FindOne(context.TODO(), bson.M{"user_id": userID}).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func createUser(user *User) {
	usersCollection.InsertOne(context.TODO(), user)
}

func updateUser(user *User) {
	usersCollection.UpdateOne(
		context.TODO(),
		bson.M{"user_id": user.UserID},
		bson.D{{Key: "$set", Value: user}},
	)
}

func isDataTooOld(user *User) bool {
	now := time.Now()
	lastCleanDate, _ := time.Parse("2006-01-02", user.LastChainCleanDate)
	lastLubeDate, _ := time.Parse("2006-01-02", user.LastChainLubeDate)

	oneMonthAgo := now.AddDate(0, -1, 0)

	return lastCleanDate.Before(oneMonthAgo) || lastLubeDate.Before(oneMonthAgo)
}

func showChainStatus(userID int64) {
	user, err := getUserByID(userID)
	if err != nil {
		sendMessage(userID, "Error fetching user data.")
		return
	}

	status := fmt.Sprintf("Chain Status:\n- Last Clean Date: %s\n- Clean Interval: %d km\n- Last Lube Date: %s\n- Lube Interval: %d km\n- Total Distance After Clean: %.2f km\n- Total Distance After Lube: %.2f km",
		user.LastChainCleanDate, user.ChainCleanInterval, user.LastChainLubeDate, user.ChainLubeInterval, user.TotalDistanceAfterClean, user.TotalDistanceAfterLube)

	msg := tgbotapi.NewMessage(userID, status)

	btnClean := tgbotapi.NewKeyboardButton("🚿 I cleaned the chain")
	btnLube := tgbotapi.NewKeyboardButton("🛢️ I lubed the chain")
	btnChangeLubeInterval := tgbotapi.NewKeyboardButton("🔧 Change chain lube interval")
	btnChangeCleanInterval := tgbotapi.NewKeyboardButton("🔧 Change chain clean interval")
	btnForgetMe := tgbotapi.NewKeyboardButton("❌ Forget me")
	btnShowStats := tgbotapi.NewKeyboardButton("📊 Show Stats")

	keyboard := tgbotapi.NewReplyKeyboard(
		tgbotapi.NewKeyboardButtonRow(btnClean, btnLube),
		tgbotapi.NewKeyboardButtonRow(btnChangeLubeInterval, btnChangeCleanInterval),
		tgbotapi.NewKeyboardButtonRow(btnForgetMe, btnShowStats),
	)

	msg.ReplyMarkup = keyboard

	bot.Send(msg)
}

func showWelcomePage(c *gin.Context) {
	c.HTML(http.StatusOK, "welcome.html", nil)
}

func handleStravaCallback(c *gin.Context) {
	code := c.Query("code")
	userID, err := strconv.ParseInt(c.Query("state"), 10, 64)
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid state")
		return
	}

	token, refreshToken, expiry, err := exchangeStravaCodeForToken(code)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to exchange code for token")
		return
	}

	updateUserField(userID, "strava_access_token", token)
	updateUserField(userID, "strava_refresh_token", refreshToken)
	updateUserField(userID, "strava_token_expiry", expiry)
	sendMessage(userID, "Strava authorization successful.")

	user, err := getUserByID(userID)
	if err != nil {
		sendMessage(userID, "Error fetching user data after Strava authorization.")
		c.String(http.StatusInternalServerError, "Error fetching user data")
		return
	}
	handleSurvey(user, "")
	c.HTML(http.StatusOK, "auth.html", nil)
}

func exchangeStravaCodeForToken(code string) (string, string, int64, error) {
	clientID := os.Getenv("STRAVA_CLIENT_ID")
	clientSecret := os.Getenv("STRAVA_CLIENT_SECRET")

	payload := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
		"grant_type":    "authorization_code",
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", "", 0, err
	}

	resp, err := http.Post("https://www.strava.com/oauth/token", "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()

	var credentials struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&credentials); err != nil {
		return "", "", 0, err
	}

	return credentials.AccessToken, credentials.RefreshToken, credentials.ExpiresAt, nil
}

func updateUserField(userID int64, field string, value interface{}) {
	usersCollection.UpdateOne(
		context.TODO(),
		bson.M{"user_id": userID},
		bson.D{{Key: "$set", Value: bson.D{{Key: field, Value: value}}}},
	)
}

func getSurveyStateByID(userID int64) (*SurveyState, error) {
	var state SurveyState
	err := usersCollection.FindOne(context.TODO(), bson.M{"user_id": userID}).Decode(&state)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return &SurveyState{UserID: userID, CurrentStep: 1}, nil
		}
		return nil, err
	}
	return &state, nil
}

func updateSurveyState(userID int64, step int) {
	usersCollection.UpdateOne(
		context.TODO(),
		bson.M{"user_id": userID},
		bson.D{{Key: "$set", Value: bson.D{{Key: "current_step", Value: step}}}},
	)
}

func deleteUserByID(userID int64) {
	usersCollection.DeleteOne(context.TODO(), bson.M{"user_id": userID})
}

func resetSurveyState(userID int64) {
	usersCollection.UpdateOne(
		context.TODO(),
		bson.M{"user_id": userID},
		bson.D{{Key: "$set", Value: bson.D{{Key: "current_step", Value: 1}}}},
	)
}

func handleSurvey(user *User, text string) {
	surveyData := []string{
		user.LastChainCleanDate,
		strconv.Itoa(user.ChainCleanInterval),
		user.LastChainLubeDate,
		strconv.Itoa(user.ChainLubeInterval),
	}

	for i, question := range Questions {
		if surveyData[i] == "" || surveyData[i] == "0" {
			if text == "" {
				sendMessage(user.UserID, question)
				return
			}

			valid := false
			switch i {
			case 0, 2:
				if isValid, errMsg := isDateValid(text); isValid {
					surveyData[i] = text
					valid = true
				} else {
					sendMessage(user.UserID, errMsg)
					return
				}
			case 1, 3:
				if val, err := strconv.Atoi(text); err == nil && val > 0 {
					surveyData[i] = strconv.Itoa(val)
					valid = true
				} else {
					sendMessage(user.UserID, "Invalid input. Please enter a positive integer.")
				}
			}

			if valid {
				updateUserSurveyData(user, surveyData)
				if i < len(Questions)-1 {
					sendMessage(user.UserID, Questions[i+1])
				} else {
					if isDataTooOld(user) {
						sendMessage(user.UserID, "It's been too long since you last cleaned/lubed your chain! Service your bike and come back! Use /start to run again.")
					} else {
						go func() {
							fetchStravaActivities(user)
							showChainStatus(user.UserID)
						}()
					}
				}
			}
			return
		}
	}

	if isDataTooOld(user) {
		sendMessage(user.UserID, "It's been too long since you last cleaned/lubed your chain! Service your bike and come back! Use /start to run again.")
	} else {
		go func() {
			fetchStravaActivities(user)
			showChainStatus(user.UserID)
		}()
	}
}

func updateUserSurveyData(user *User, surveyData []string) {
	user.LastChainCleanDate = surveyData[0]
	user.ChainCleanInterval, _ = strconv.Atoi(surveyData[1])
	user.LastChainLubeDate = surveyData[2]
	user.ChainLubeInterval, _ = strconv.Atoi(surveyData[3])

	updateUser(user)
}

func parseDateToUnix(dateStr string) int64 {
	date, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		date, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			log.Printf("Error parsing date: %v", err)
			return 0
		}
	}
	return date.Unix()
}

func startStravaDataFetcher() {
	for {
		now := time.Now()
		next := now.Add(time.Hour * 2)
		next = time.Date(next.Year(), next.Month(), next.Day(), next.Hour(), 0, 0, 0, next.Location())
		duration := next.Sub(now)

		time.AfterFunc(duration, func() {
			updateAllUsersStravaData()
			startStravaDataFetcher()
		})

		time.Sleep(duration + time.Minute)
	}
}

func updateAllUsersStravaData() {
	cursor, err := usersCollection.Find(context.TODO(), bson.M{})
	if err != nil {
		log.Printf("Failed to fetch users: %v", err)
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var user User
		if err := cursor.Decode(&user); err != nil {
			log.Printf("Failed to decode user: %v", err)
			continue
		}

		if user.StravaAccessToken != "" {
			if err := fetchStravaActivities(&user); err != nil {
				log.Printf("Failed to fetch Strava activities for user %d: %v", user.UserID, err)
			}
		}
		time.Sleep(time.Minute)
	}

	if err := cursor.Err(); err != nil {
		log.Printf("Cursor error: %v", err)
	}
}

func sendMessageWithStatus(userID int64, text string) {
	user, err := getUserByID(userID)
	if err != nil {
		sendMessage(userID, "Error fetching user data.")
		return
	}

	status := fmt.Sprintf("%s\n\nChain Status:\n- Last Clean Date: %s\n- Clean Interval: %d km\n- Last Lube Date: %s\n- Lube Interval: %d km\n- Total Distance After Clean: %.2f km\n- Total Distance After Lube: %.2f km",
		text, user.LastChainCleanDate, user.ChainCleanInterval, user.LastChainLubeDate, user.ChainLubeInterval, user.TotalDistanceAfterClean, user.TotalDistanceAfterLube)

	sendMessage(userID, status)
}

func fetchStravaActivities(user *User) error {
	if user.StravaTokenExpiry < time.Now().Unix() {
		if err := refreshStravaToken(user); err != nil {
			return err
		}
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://www.strava.com/api/v3/athlete/activities", nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return err
	}

	req.Header.Set("Authorization", "Bearer "+user.StravaAccessToken)
	cleanDateUnix := parseDateToUnix(user.LastChainCleanDate)
	lubeDateUnix := parseDateToUnix(user.LastChainLubeDate)

	query := req.URL.Query()
	query.Add("after", strconv.FormatInt(cleanDateUnix, 10))
	query.Add("per_page", "100")
	req.URL.RawQuery = query.Encode()

	log.Printf("Request URL: %s", req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error performing request: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		log.Printf("Failed to fetch activities: %s, Response body: %s", resp.Status, bodyString)
		return fmt.Errorf("failed to fetch activities: %s", resp.Status)
	}

	var activities []Activity
	if err := json.NewDecoder(resp.Body).Decode(&activities); err != nil {
		log.Printf("Error decoding response: %v", err)
		return err
	}

	log.Printf("Fetched %d activities", len(activities))

	var totalDistanceAfterClean float64
	var totalDistanceAfterLube float64

	for _, activity := range activities {
		if activity.Type == "Ride" {
			startDate := parseDateToUnix(activity.StartDate)
			if startDate >= cleanDateUnix {
				totalDistanceAfterClean += activity.Distance
			}
			if startDate >= lubeDateUnix {
				totalDistanceAfterLube += activity.Distance
			}
		}
	}

	user.TotalDistanceAfterClean = totalDistanceAfterClean / 1000 // Convert meters to kilometers
	user.TotalDistanceAfterLube = totalDistanceAfterLube / 1000   // Convert meters to kilometers

	updateUser(user)
	log.Printf("Updated user %d: TotalDistanceAfterClean=%.2f, TotalDistanceAfterLube=%.2f", user.UserID, user.TotalDistanceAfterClean, user.TotalDistanceAfterLube)

	if user.TotalDistanceAfterClean >= float64(user.ChainCleanInterval) {
		sendMessageWithStatus(user.UserID, "Time to clean your chain!")
	}

	if user.TotalDistanceAfterLube >= float64(user.ChainLubeInterval) {
		sendMessageWithStatus(user.UserID, "Time to lube your chain!")
	}

	return nil
}

func refreshStravaToken(user *User) error {
	clientID := os.Getenv("STRAVA_CLIENT_ID")
	clientSecret := os.Getenv("STRAVA_CLIENT_SECRET")

	payload := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"grant_type":    "refresh_token",
		"refresh_token": user.StravaRefreshToken,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post("https://www.strava.com/oauth/token", "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var credentials struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&credentials); err != nil {
		return err
	}

	user.StravaAccessToken = credentials.AccessToken
	user.StravaRefreshToken = credentials.RefreshToken
	user.StravaTokenExpiry = credentials.ExpiresAt

	updateUser(user)
	return nil
}
