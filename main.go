package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

type User struct {
	FirstName string `json:firstName`
	LastName  string `json:lastName`
}

type Phone struct {
	Number  string `json:number`
	Country string `json:country`
}

type Wallet struct {
	Address string `json:address`
	Token   string `json:country`
}

type JwtClaims struct {
	Name string `json:name`
	jwt.StandardClaims
}

func renderHome(c echo.Context) error {
	return c.String(http.StatusOK, "Server over here!")
}

func getUser(c echo.Context) error {
	first := c.QueryParam("firstName")
	last := c.QueryParam("lastName")
	dataType := c.Param("data")

	if dataType == "string" {
		return c.String(http.StatusOK, fmt.Sprintf("First name: %s\nLast Name: %s\n", first, last))
	}

	if dataType == "json" {
		return c.JSON(http.StatusOK, map[string]string{
			"firstName": first,
			"lastName":  last,
		})
	}

	return c.JSON(http.StatusBadRequest, map[string]string{
		"error": "We need to know if you want JSON back or string data",
	})

}

func addUser(c echo.Context) error {
	user := User{}

	defer c.Request().Body.Close()
	b, err := ioutil.ReadAll(c.Request().Body)

	if err != nil {
		log.Printf("Failed reading the request body for addUser: %s", err)
		return c.String(http.StatusInternalServerError, "")
	}

	err = json.Unmarshal(b, &user)
	if err != nil {
		log.Printf("Failed unmarshaling in addUser : %s", err)
	}

	log.Printf("This is the user: %#v", user)
	return c.String(http.StatusOK, "We have a user!")

}

func addPhone(c echo.Context) error {
	phone := Phone{}
	defer c.Request().Body.Close()

	err := json.NewDecoder(c.Request().Body).Decode(&phone)
	if err != nil {
		log.Printf("Failed processing addPhoneNumber request: %s", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	log.Printf("This is the user: %#v", phone)
	return c.String(http.StatusOK, "We have added a new phone number!")
}

func addWalletAddress(c echo.Context) error {
	wallet := Wallet{}

	err := c.Bind(&wallet)
	if err != nil {
		log.Printf("Failed processing addWalletAddress request: %s", err)
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	log.Printf("Here is the wallet address: %#v", wallet)
	return c.String(http.StatusOK, "Successfuly added a new wallet address!")
}

func getMainAdmin(c echo.Context) error {
	return c.String(http.StatusOK, "You are on secret admin page")
}

func mainCookie(c echo.Context) error {
	return c.String(http.StatusOK, "You are on the clear cookie page.")
}

func mainJwt(c echo.Context) error {
	return c.String(http.StatusOK, "You are on the correct JWT page!")
}

func login(c echo.Context) error {
	username := c.QueryParam("username")
	password := c.QueryParam("password")

	// check username nd password in DB after hash
	if username == "foo" && password == "bar" {
		cookie := &http.Cookie{}

		cookie.Name = "sessionID"
		cookie.Value = "random_string"
		cookie.Expires = time.Now().Add(48 * time.Hour)

		c.SetCookie(cookie)

		// TODO: create jwt token
		token, err := createJwtToken()
		if err != nil {
			log.Println("Error creating JWT token", err)
			return c.String(http.StatusInternalServerError, "Something went  wrong")
		}

		return c.JSON(http.StatusOK, map[string]string{
			"message": "You were succesfuly logged in",
			"token":   token,
		})
	}

	return c.String(http.StatusUnauthorized, "Wrong username or password")
}

func createJwtToken() (string, error) {
	claims := JwtClaims{
		"fode",
		jwt.StandardClaims{
			Id:        "main_user_id",
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
	}

	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	token, err := rawToken.SignedString([]byte("Not_So_Secret"))
	if err != nil {
		return "", err
	}

	return token, nil
}

////////////////////////// Middlewares ////////////////////////////

func ServerHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set(echo.HeaderServer, "ToshiText/1.0")
		return next(c)
	}
}

func checkCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		cookie, err := c.Cookie("sessionID")
		if err != nil {
			if strings.Contains(err.Error(), "named cookie not present") {
				return c.String(http.StatusUnauthorized, "You don't have any cookie foo!")
			}
			log.Println(err)
			return err
		}

		if cookie.Value == "random_string" {
			return next(c)
		}

		return c.String(http.StatusUnauthorized, "You don't have the right chocolate cookie")

	}
}

func main() {
	fmt.Println("Live from the server...")

	e := echo.New()

	e.Use(ServerHeader)

	adminGroup := e.Group("/admin")
	cookieGroup := e.Group("/cookie")
	jwtGroup := e.Group("/jwt")

	// Log the server interaction
	adminGroup.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `[${time_rfc3339}] ${status} ${method} ${host}${path} ${latency_human}` + "\n",
	}))

	adminGroup.Use(middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {

		// check in the DB in password is valid
		if username == "fode" && password == "54321" {
			return true, nil
		}
		return false, nil
	}))

	jwtGroup.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		SigningMethod: "HS512",
		SigningKey:    []byte("Not_So_Secret"),
	}))

	cookieGroup.Use(checkCookie)

	adminGroup.GET("/main", getMainAdmin)
	cookieGroup.GET("/main", mainCookie)
	jwtGroup.GET("/main", mainJwt)

	e.GET("/", renderHome)
	e.GET("/login", login)
	e.GET("/users/:data", getUser)

	e.POST("/users", addUser)
	e.POST("/phones", addPhone)
	e.POST("/wallets", addWalletAddress)

	e.Start(":8000")
}
