package main

import jwt "github.com/dgrijalva/jwt-go"

func main() { _ = jwt.New(jwt.SigningMethodHS256) }
