package main

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

func blindfoldKey(key string) {}

// getSecretPolicyDocument queries the tenant's API for the secret policy document.
func getSecretPolicyDocument(tenantUrl, tenantToken, policyDocName string) (string, error) {
	// Construct the full API URL
	var apiUrl string

	if policyDocName == "" {
		apiUrl = fmt.Sprintf("%s/api/secret_management/namespaces/shared/secret_policys/ves-io-allow-volterra/get_policy_document", tenantUrl)
	} else {
		apiUrl = fmt.Sprintf("%s/api/secret_management/namespaces/shared/secret_policys/%s/get_policy_document", tenantUrl, policyDocName)
	}

	// Create a new request
	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %v", err)
	}

	// Add the Authorization header
	req.Header.Add("Authorization", "APIToken "+tenantToken)

	// Set up the HTTP client
	client := &http.Client{
		Timeout: time.Second * 30, // 30-second timeout; adjust as needed
	}

	// Perform the request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("performing request: %v", err)
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-200 response status: %d", resp.StatusCode)
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %v", err)
	}

	return string(body), nil
}

func getTenantPublicKey(tenantUrl, tenantToken string) (string, error) {
	// Construct the full API URL
	apiUrl := fmt.Sprintf("%s/api/secret_management/get_public_key", tenantUrl)

	// Create a new request
	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %v", err)
	}

	// Add the Authorization header
	req.Header.Add("Authorization", "APIToken "+tenantToken)

	// Set up the HTTP client
	client := &http.Client{
		Timeout: time.Second * 30, // Adjust the timeout as needed
	}

	// Perform the request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("performing request: %v", err)
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-200 response status: %d - %s", resp.StatusCode, resp.Status)
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %v", err)
	}

	return string(body), nil
}

func showSignupForm(c *gin.Context) {
	c.HTML(http.StatusOK, "signup.html", nil)
}

func showHomePage(c *gin.Context) {
	c.HTML(200, "index.html", nil)
}

func (app *App) handleSignup(c *gin.Context) {
	db := app.DB // Obtain *sql.DB instance

	// Parse form data
	username := c.PostForm("username")
	password := c.PostForm("password")

	// Check if the username exists
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM Users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"message": "Database error"})
		return
	}
	if exists {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"message": "Username already exists"})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"message": "Error hashing password"})
		return
	}

	// Determine the role for the new user
	var userCount int
	err = db.QueryRow("SELECT COUNT(*) FROM Users").Scan(&userCount)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"message": "Failed to determine user count"})
		return
	}

	role := "user" // Default role
	if userCount == 0 {
		role = "admin" // First user gets the 'admin' role
	}

	// Insert new user with the determined role
	_, err = db.Exec("INSERT INTO Users (username, passwordHash, role, lastLogin) VALUES (?, ?, ?, datetime('now'))", username, string(hashedPassword), role)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"message": "Could not create user"})
		return
	}

	// Redirect to operations
	if role == "user" {
		c.Redirect(http.StatusFound, "/operations")
	} else if role == "admin" {
		c.Redirect(http.StatusFound, "/admin")
	}
}

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		authenticated := session.Get("authenticated")
		if authenticated == nil {
			// User is not authenticated
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (app *App) showOperationForm(c *gin.Context) {
	session := sessions.Default(c)
	currentUsername := session.Get("username")
	if currentUsername == nil {
		// Handle case where username is not set in the session, e.g., user is not logged in
		c.Redirect(http.StatusFound, "/login")
		return
	}
	// Fetch existing tokens from the database
	var apiTokens []APIToken

	rows, err := app.DB.Query("SELECT createdAt, id FROM APITokens WHERE username = ?", currentUsername) // Adjust for actual user
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"message": "Database error"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var token APIToken

		if err := rows.Scan(&token.CreatedAt, &token.Id); err != nil {
			// handle this error
		}
		apiTokens = append(apiTokens, token)
	}

	newToken := c.Query("newToken")
	// Render the page
	c.HTML(http.StatusOK, "operations.html", gin.H{
		"Tokens":         apiTokens,
		"GeneratedToken": newToken,
	})
}

func (app *App) showAdminForm(c *gin.Context) {
	session := sessions.Default(c)
	currentUsername := session.Get("username")
	if currentUsername == nil {
		// Handle case where username is not set in the session
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// Assuming currentUsername is a string; ensure type assertion if necessary
	usernameStr, ok := currentUsername.(string)
	if !ok {
		// Handle case where username is not a string or not set correctly
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// Fetch users from the database
	var users []User
	userRows, err := app.DB.Query("SELECT username, role, lastLogin, uid FROM Users")
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"message": "Database error"})
		return
	}
	defer userRows.Close()

	for userRows.Next() {
		var user User
		if err := userRows.Scan(&user.Username, &user.Role, &user.LastLogin, &user.Uid); err != nil {
			fmt.Printf("Error: %s", err)
			continue // or log the error
		}
		users = append(users, user)
	}

	// Fetch API tokens for the current user
	var apiTokens []APIToken
	tokenRows, err := app.DB.Query("SELECT id, createdAt FROM APITokens WHERE username = ?", usernameStr)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"message": "Database error fetching tokens"})
		return
	}
	defer tokenRows.Close()

	for tokenRows.Next() {
		var token APIToken
		if err := tokenRows.Scan(&token.Id, &token.CreatedAt); err != nil {
			continue // or log the error
		}
		apiTokens = append(apiTokens, token)
	}

	// Capture newToken query parameter
	newToken := c.Query("newToken")

	c.HTML(http.StatusOK, "admin.html", gin.H{
		"Users":          users,
		"Tokens":         apiTokens,
		"GeneratedToken": newToken,
	})
}

func showLoginForm(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

func (app *App) handleLogin(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	// Fetch user from the database
	var storedHash string
	var role string
	err := app.DB.QueryRow("SELECT passwordHash, role FROM Users WHERE username = ?", username).Scan(&storedHash, &role)
	if err != nil {
		// User not found or database error
		c.HTML(http.StatusBadRequest, "login.html", gin.H{"message": "Invalid username or password"})
		return
	}

	// Compare the hashed password
	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err != nil {
		// Password does not match
		c.HTML(http.StatusBadRequest, "login.html", gin.H{"message": "Invalid username or password"})
		return
	}

	// After successfully authenticating the user
	session := sessions.Default(c)
	session.Set("authenticated", true)
	session.Set("username", username) // Optionally store the username in the session
	session.Save()

	_, err = app.DB.Exec("UPDATE Users SET lastLogin = datetime('now') WHERE username = ?", username)

	//Redirect based on role
	if role == "admin" {
		c.Redirect(http.StatusFound, "/admin")
	} else {
		c.Redirect(http.StatusFound, "/operations")
	}

}

func (app *App) handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, "/login")
}

func (app *App) deleteUser(c *gin.Context) {
	username := c.PostForm("username")
	_, err := app.DB.Exec("DELETE FROM Users WHERE username = ?", username)
	if err != nil {
		// Handle error
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"message": "Failed to delete user"})
		return
	}

	// Redirect back to the admin page or display a success message
	c.Redirect(http.StatusFound, "/admin")
}
func (app *App) deleteToken(c *gin.Context) {
	session := sessions.Default(c)
	currentUsername := session.Get("username")
	if currentUsername == nil {
		// Handle case where username is not set in the session
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// Assuming currentUsername is a string; ensure type assertion if necessary
	usernameStr, ok := currentUsername.(string)
	if !ok {
		// Handle case where username is not a string or not set correctly
		c.Redirect(http.StatusFound, "/login")
		return
	}

	tokenId := c.PostForm("tokenId")
	if tokenId == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"message": "Token ID is required"})
		return
	}

	// Assuming you're using a SQL database
	_, err := app.DB.Exec("DELETE FROM APITokens WHERE id = ?", tokenId)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"message": "Failed to delete token"})
		return
	}

	// Query the database for the user's role
	var role string
	err = app.DB.QueryRow("SELECT role FROM Users WHERE username = ?", usernameStr).Scan(&role)
	if err != nil {
		// Handle error - Could not find user or database error
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"message": "Failed to retrieve user role: " + err.Error()})
		return
	}

	// // Redirect back to the operations page, or you can render a success message
	// if role == "admin" {
	// 	c.Redirect(http.StatusFound, "/admin")
	// } else if role == "user" {
	// 	c.Redirect(http.StatusFound, "/operations")
	// }
	referer := c.Request.Header.Get("Referer")
	if referer != "" {
		c.Redirect(http.StatusFound, referer)
	} else {
		// Default redirection if no valid referer is found
		c.Redirect(http.StatusFound, "/") // Adjust the default redirect as necessary
	}
}

func (app *App) generateToken(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	if username == nil {
		// Handle case where username is not set in the session, e.g., user is not logged in
		c.Redirect(http.StatusFound, "/login")
		return
	}

	newToken := uuid.NewString()

	b64Token := base64.StdEncoding.EncodeToString([]byte(newToken))

	_, err := app.DB.Exec("INSERT INTO APITokens (token, username) VALUES (?, ?)", b64Token, username)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"message": "Failed to generate token: " + err.Error()})
		return
	}

	// Query the database for the user's role
	var role string
	err = app.DB.QueryRow("SELECT role FROM Users WHERE username = ?", username).Scan(&role)
	if err != nil {
		// Handle error - Could not find user or database error
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"message": "Failed to retrieve user role: " + err.Error()})
		return
	}

	referer := c.Request.Header.Get("Referer")
	refererURL, err := url.Parse(referer)

	if err != nil || referer == "" {
		// Handle error or lack of referer by redirecting to a default location
		c.Redirect(http.StatusFound, "/")
		return
	}

	query := refererURL.Query()
	query.Set("newToken", b64Token)
	refererURL.RawQuery = query.Encode()

	// Redirect to the referer URL with the newToken query parameter added
	c.Redirect(http.StatusFound, refererURL.String())
}

// initializeDatabaseTables creates the necessary tables if they don't exist.
func initializeDatabaseTables(db *sql.DB) error {
	// SQL statement for creating the Users table
	createUsersTableSQL := `
    CREATE TABLE IF NOT EXISTS Users (
        uid INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        passwordHash TEXT NOT NULL,
        role TEXT NOT NULL,
        lastLogin DATETIME,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    );`

	// Updated SQL statement for creating the APITokens table with a createdAt field
	createAPITokensTableSQL := `CREATE TABLE IF NOT EXISTS APITokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (username) REFERENCES Users(username)
    );`

	// Execute the SQL statements to create the tables
	if _, err := db.Exec(createUsersTableSQL); err != nil {
		return err
	}

	if _, err := db.Exec(createAPITokensTableSQL); err != nil {
		return err
	}

	return nil
}

func main() {
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	// Set up cookie-based session middleware
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	db, err := sql.Open("sqlite3", "./blindfold_api.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	app := &App{DB: db}

	// Initialize database tables
	if err := initializeDatabaseTables(db); err != nil {
		log.Fatal("Failed to initialize tables: ", err)
	}

	log.Println("Database initialized successfully")

	r.GET("/", showHomePage)
	r.GET("/signup", showSignupForm)
	r.GET("/operations", AuthRequired(), app.showOperationForm)
	r.GET("/admin", AuthRequired(), app.showAdminForm)
	r.POST("/signup", app.handleSignup)
	r.GET("/login", showLoginForm)
	r.POST("/login", app.handleLogin)
	r.POST("/delete-user", AuthRequired(), app.deleteUser)
	r.POST("/delete-token", AuthRequired(), app.deleteToken)
	r.POST("/generate-token", AuthRequired(), app.generateToken)
	r.POST("/logout", app.handleLogout)

	r.POST("/blindfold-key", func(c *gin.Context) {
		// Parse request, validate API key, and perform operations
		// Dummy implementation
		c.JSON(http.StatusOK, gin.H{"result": "success"})
	})

	// Get port from environment variable
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port if not specified
	}

	// Start the server on the environment-specified port
	log.Printf("Server starting on http://127.0.0.1:%s\n", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}
